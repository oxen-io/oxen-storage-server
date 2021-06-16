#include "Database.hpp"
#include "SQLiteCpp/Statement.h"
#include "SQLiteCpp/Transaction.h"
#include "oxen_logger.h"
#include "string_utils.hpp"
#include "time.hpp"
#include "utils.hpp"
#include "Owner.hpp"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <shared_mutex>
#include <thread>
#include <unordered_set>

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

namespace oxen {
using namespace storage;

constexpr std::chrono::milliseconds SQLite_busy_timeout = 3s;

namespace {

template <typename T> constexpr bool is_cstr = false;
template <size_t N> constexpr bool is_cstr<char[N]> = true;
template <size_t N> constexpr bool is_cstr<const char[N]> = true;
template <> constexpr bool is_cstr<char*> = true;
template <> constexpr bool is_cstr<const char*> = true;

// Simple wrapper class that can be used to bind a blob through the templated binding code below.
// E.g. `exec_query(st, 100, 42, blob_binder{data})` binds the third parameter using no-copy blob
// binding of the contained data.
struct blob_binder {
    std::string_view data;
    explicit blob_binder(std::string_view d) : data{d} {}
};

// Binds a string_view as a no-copy blob at parameter index i.
void bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob) {
    st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
}

// Called from exec_query and similar to bind statement parameters for immediate execution.  strings
// (and c strings) use no-copy binding; user_pubkey_t values use *two* sequential binding slots for
// pubkey (first) and type (second); integer values are bound by value.  You can bind a blob (by
// reference, like strings) by passing `blob_binder{data}`.
template <typename T>
void bind_oneshot(SQLite::Statement& st, int& i, const T& val) {
    if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
        st.bindNoCopy(i++, val);
    else if constexpr (std::is_same_v<T, blob_binder>)
        bind_blob_ref(st, i++, val.data);
    else if constexpr (std::is_same_v<T, user_pubkey_t>) {
        bind_blob_ref(st, i++, val.raw());
        st.bind(i++, val.type());
    }
    else
        st.bind(i++, val);
}

// Binds pubkey in a query such as `... WHERE pubkey = ? AND type = ?` into positions i (pubkey) and
// j (type).  The user_pubkey_t reference must stay valid for the duration of the statement.
void bind_pubkey(SQLite::Statement& st, int i, int j, const user_pubkey_t& pk) {
    bind_blob_ref(st, i, pk.raw());
    st.bind(j, pk.type());
}

// Executes a query that does not expect results.  Optionally binds parameters, if provided.
// Returns the number of affected rows; throws on error or if results are returned.
template <typename... T>
int exec_query(SQLite::Statement& st, const T&... bind) {
    int i = 1;
    (bind_oneshot(st, i, bind), ...);
    return st.exec();
}

// Same as above, but prepares a literal query on the fly for use with queries that are only used
// once.
template <typename... T>
int exec_query(SQLite::Database& db, const char* query, const T&... bind) {
    SQLite::Statement st{db, query};
    return exec_query(st, bind...);
}


template <typename T, typename... More>
struct first_type { using type = T; };
template <typename... T> using first_type_t = typename first_type<T...>::type;

template <typename... T> using type_or_tuple = std::conditional_t<sizeof...(T) == 1, first_type_t<T...>, std::tuple<T...>>;

// Retrieves a single row of values from the current state of a statement (i.e. after a
// executeStep() call that is expecting a return value).  If `T...` is a single type then this
// returns the single T value; if T... has multiple types then you get back a tuple of values.
template <typename T>
T get(SQLite::Statement& st) {
    return static_cast<T>(st.getColumn(0));
}
template <typename T1, typename T2, typename... Tn>
std::tuple<T1, T2, Tn...> get(SQLite::Statement& st) {
    return st.getColumns<std::tuple<T1, T2, Tn...>, 2 + sizeof...(Tn)>();
}

// Steps a statement to completion that is expected to return at most one row, optionally binding
// values into it (if provided).  Returns a filled out optional<T> (or optional<std::tuple<T...>>)
// if a row was retrieved, otherwise a nullopt.  Throws if more than one row is retrieved.
template <typename... T, typename... Args>
std::optional<type_or_tuple<T...>> exec_and_maybe_get(SQLite::Statement& st, const Args&... bind) {
    int i = 1;
    (bind_oneshot(st, i, bind), ...);
    std::optional<type_or_tuple<T...>> result;
    while (st.executeStep()) {
        if (result) {
            OXEN_LOG(err, "Expected single-row result, got multiple rows from {}", st.getQuery());
            throw std::runtime_error{"DB error: expected single-row result, got multiple rows"};
        }
        result = get<T...>(st);
    }
    return result;
}

// Executes a statement to completion that is expected to return exactly one row, optionally binding
// values into it (if provided).  Returns a T or std::tuple<T...> (depending on whether or not more
// than one T is provided) for the row.  Throws an exception if no rows or more than one row are
// returned.
template <typename... T, typename... Args>
type_or_tuple<T...> exec_and_get(SQLite::Statement& st, const Args&... bind) {
    auto maybe_result = exec_and_maybe_get<T...>(st, bind...);
    if (!maybe_result) {
        OXEN_LOG(err, "Expected single-row result, got no rows from {}", st.getQuery());
        throw std::runtime_error{"DB error: expected single-row result, got not rows"};
    }
    return *std::move(maybe_result);
}

// Executes a query to completion, collecting each row into a vector<T> (or vector<tuple<T...>> if
// multiple T are given).  Can optionally bind before executing.
template <typename... T, typename... Bind>
std::vector<type_or_tuple<T...>> get_all(SQLite::Statement& st, const Bind&... bind) {
    int i = 1;
    (bind_oneshot(st, i, bind), ...);
    std::vector<type_or_tuple<T...>> results;
    while (st.executeStep())
        results.push_back(get<T...>(st));
    return results;
}

} // anon. namespace

class DatabaseImpl {
public:

    oxen::Database& parent;
    SQLite::Database db;

    // keep track of db full errorss so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

    // SQLiteCpp's statements are not thread-safe, so we prepare them thread-locally when needed
    std::unordered_map<std::thread::id, std::unordered_map<std::string, SQLite::Statement>> prepared_sts;
    std::shared_mutex prepared_sts_mutex;

    int page_size;

    DatabaseImpl(Database& parent, const std::filesystem::path& db_path) :
        parent{parent},
        db{
            db_path / std::filesystem::u8path("storage.db"),
            SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX,
            SQLite_busy_timeout.count()
        }
    {
        // Don't fail on these because we can still work even if they fail
        if (int rc = db.tryExec("PRAGMA journal_mode = WAL");
                rc != SQLITE_OK)
            OXEN_LOG(err, "Failed to set journal mode to WAL: {}", sqlite3_errstr(rc));

        if (int rc = db.tryExec("PRAGMA synchronous = NORMAL");
                rc != SQLITE_OK)
            OXEN_LOG(err, "Failed to set synchronous mode to NORMAL: {}", sqlite3_errstr(rc));

        page_size = db.execAndGet("PRAGMA page_size").getInt();
        // Would use a placeholder here, but sqlite3 apparently doesn't support them for PRAGMAs.
        if (int rc = db.tryExec("PRAGMA max_page_count = " + std::to_string(Database::SIZE_LIMIT / page_size));
                rc != SQLITE_OK) {
            auto m = fmt::format("Failed to set max page count: {}", sqlite3_errstr(rc));
            OXEN_LOG(critical, m);
            throw std::runtime_error{m};
        }

        if (!db.tableExists("owners")) {
            create_schema();
        }
    }

    void create_schema() {

        SQLite::Transaction transaction{db};

        db.exec(R"(
CREATE TABLE owners (
    id INTEGER PRIMARY KEY,
    type INTEGER NOT NULL,
    pubkey BLOB NOT NULL,

    UNIQUE(pubkey, type)
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    owner INTEGER NOT NULL REFERENCES owners(id),
    timestamp INTEGER NOT NULL,
    expiry INTEGER NOT NULL,
    data BLOB NOT NULL,

    UNIQUE(hash)
);

CREATE INDEX messages_expiry ON messages(expiry);
CREATE INDEX messages_owner ON messages(owner, timestamp);

CREATE TRIGGER owner_autoclean
    AFTER DELETE ON messages FOR EACH ROW WHEN NOT EXISTS (SELECT * FROM messages WHERE owner = old.owner)
    BEGIN
        DELETE FROM owners WHERE id = old.owner;
    END;

CREATE VIEW owned_messages AS
    SELECT owners.id AS oid, type, pubkey, messages.id AS mid, hash, timestamp, expiry, data
    FROM messages JOIN owners ON messages.owner = owners.id;

CREATE TRIGGER owned_messages_insert
    INSTEAD OF INSERT ON owned_messages FOR EACH ROW WHEN NEW.oid IS NULL
    BEGIN
        INSERT INTO owners (type, pubkey) VALUES (NEW.type, NEW.pubkey) ON CONFLICT DO NOTHING;
        INSERT INTO messages values (
            NEW.mid,
            NEW.hash,
            (SELECT id FROM owners WHERE type = NEW.type AND pubkey = NEW.pubkey),
            NEW.timestamp,
            NEW.expiry,
            NEW.data);
    END;

        )");

        if (db.tableExists("Data")) {
            OXEN_LOG(warn, "Old database schema detected; performing migration...");

            // Migratation from old table structure:
            //
            // CREATE TABLE Data(
            //    Hash VARCHAR(128) NOT NULL,
            //    Owner VARCHAR(256) NOT NULL,
            //    TTL INTEGER NOT NULL,
            //    Timestamp INTEGER NOT NULL,
            //    TimeExpires INTEGER NOT NULL,
            //    Nonce VARCHAR(128) NOT NULL,
            //    Data BLOB
            // );

            SQLite::Statement ins_owner{db, "INSERT INTO owners (type, pubkey) VALUES (?, ?) RETURNING id"};

            std::unordered_map<std::string, int> owner_ids;
            SQLite::Statement old_owners{db, "SELECT DISTINCT Owner FROM Data"};
            while (old_owners.executeStep()) {
                int type;
                std::array<char, 32> pubkey;
                std::string old_owner = old_owners.getColumn(1);
                if (old_owner.size() == 66 && util::starts_with(old_owner, "05") && oxenmq::is_hex(old_owner)) {
                    type = 5;
                    oxenmq::from_hex(old_owner.begin() + 2, old_owner.end(), pubkey.begin());
                } else if (old_owner.size() == 64 && oxenmq::is_hex(old_owner)) {
                    type = 0;
                    oxenmq::from_hex(old_owner.begin(), old_owner.end(), pubkey.begin());
                } else {
                    OXEN_LOG(warn, "Found invalid owner pubkey '{}' during migration; ignoring");
                    continue;
                }

                int id = exec_and_get<int>(ins_owner, type, old_owner);
                owner_ids.emplace(std::move(old_owner), id);
            }

            OXEN_LOG(warn, "Migrated {} owner pubkeys.  Migrating messages...", owner_ids.size());

            SQLite::Statement ins_msg{db,
                "INSERT INTO messages (hash, owner, timestamp, expiry, data) VALUES (?, ?, ?, ?, ?)"};

            SQLite::Statement sel_msgs{db,
                "SELECT Hash, Owner, Timestamp, TimeExpires, Data FROM Data ORDER BY rowid"};
            int msgs = 0, bad_owners = 0;
            while (sel_msgs.executeStep()) {
                auto [hash, owner, ts, exp, data] = get<const char*, const char*, int64_t, int64_t, std::string>(sel_msgs);
                auto it = owner_ids.find(owner);
                if (it == owner_ids.end()) {
                    bad_owners++;
                    continue;
                }
                exec_query(ins_msg, hash, it->second, ts, exp, data);
                msgs++;
            }

            OXEN_LOG(warn, "Migrated {} messages ({} invalid owner ids); dropping old Data table",
                    msgs, bad_owners);

            db.exec("DROP TABLE Data");

            OXEN_LOG(warn, "Data migration complete!");
        }

        transaction.commit();

        OXEN_LOG(info, "Database setup complete");
    }

    /** Wrapper around a SQLite::Statement that calls `tryReset()` on destruction of the wrapper. */
    class StatementWrapper {
        SQLite::Statement& st;
    public:
        /// Whether we should reset on destruction; can be set to false if needed.
        bool reset_on_destruction = true;

        explicit StatementWrapper(SQLite::Statement& st) noexcept : st{st} {}
        ~StatementWrapper() noexcept { if (reset_on_destruction) st.tryReset(); }
        SQLite::Statement& operator*() noexcept { return st; }
        SQLite::Statement* operator->() noexcept { return &st; }
        operator SQLite::Statement&() noexcept { return st; }
    };


    StatementWrapper prepared_st(const std::string& query) {
        std::unordered_map<std::string, SQLite::Statement>* sts;
        {
            std::shared_lock rlock{prepared_sts_mutex};
            if (auto it = prepared_sts.find(std::this_thread::get_id());
                    it != prepared_sts.end())
                sts = &it->second;
            else {
                rlock.unlock();
                std::unique_lock wlock{prepared_sts_mutex};
                sts = &prepared_sts.try_emplace(std::this_thread::get_id()).first->second;
            }
        }
        if (auto qit = sts->find(query); qit != sts->end())
            return StatementWrapper{qit->second};
        return StatementWrapper{sts->try_emplace(query, db, query).first->second};
    }

    template <typename... T>
    int prepared_exec(const std::string& query, const T&... bind) {
        return exec_query(prepared_st(query), bind...);
    }

    template <typename... T, typename... Bind>
    auto prepared_get(const std::string& query, const Bind&... bind) {
        return exec_and_get<T...>(prepared_st(query), bind...);
    }

    user_pubkey_t load_pubkey(uint8_t type, std::string pk) {
        return {type, std::move(pk)};
    }
};

Database::Database(const std::filesystem::path& db_path)
    : impl{std::make_unique<DatabaseImpl>(*this, db_path)}
{
    clean_expired();
}

Database::~Database() = default;

void Database::clean_expired() {
    impl->prepared_exec("DELETE FROM messages WHERE expiry <= ?",
            to_epoch_ms(std::chrono::system_clock::now()));
}

int64_t Database::get_message_count() {
    return impl->prepared_get<int64_t>("SELECT COUNT(*) FROM messages");
}

int64_t Database::get_owner_count() {
    return impl->prepared_get<int64_t>("SELECT COUNT(*) FROM owners");
}

int64_t Database::get_used_bytes() {
    return impl->prepared_get<int64_t>("PRAGMA page_count") * impl->page_size;
}

static std::optional<message_t> get_message(DatabaseImpl& impl, SQLite::Statement& st) {
    std::optional<message_t> msg;
    while (st.executeStep()) {
        assert(!msg);
        auto [hash, otype, opubkey, ts, exp, data] = get<std::string, uint8_t, std::string, int64_t, int64_t, std::string>(st);
        msg.emplace(
            impl.load_pubkey(otype, std::move(opubkey)),
            std::move(hash),
            from_epoch_ms(ts),
            from_epoch_ms(exp),
            std::move(data));
    }
    return msg;
}

std::optional<message_t> Database::retrieve_random() {
    clean_expired();
    auto st = impl->prepared_st("SELECT hash, type, pubkey, timestamp, expiry, data"
        " FROM owned_messages "
        " WHERE mid = (SELECT id FROM messages ORDER BY RANDOM() LIMIT 1)");
    return get_message(*impl, st);
}

std::optional<message_t> Database::retrieve_by_hash(const std::string& msg_hash) {
    auto st = impl->prepared_st("SELECT hash, type, pubkey, timestamp, expiry, data"
            " FROM owned_messages WHERE hash = ?");
    st->bindNoCopy(1, msg_hash);
    return get_message(*impl, st);
}

std::optional<bool> Database::store(const message_t& msg) {
    auto st = impl->prepared_st("INSERT INTO owned_messages"
           " (pubkey, type, hash, timestamp, expiry, data) VALUES (?, ?, ?, ?, ?, ?)");

    try {
        exec_query(st,
            msg.pubkey,
            msg.hash,
            to_epoch_ms(msg.timestamp),
            to_epoch_ms(msg.expiry),
            blob_binder{msg.data});
    } catch (const SQLite::Exception& e) {
        if (int rc = e.getErrorCode(); rc == SQLITE_CONSTRAINT)
            return false;
        else if (rc == SQLITE_FULL) {
            if (impl->db_full_counter++ % DB_FULL_FREQUENCY == 0)
                OXEN_LOG(err, "Failed to store message: database is full");
            return std::nullopt;
        } else {
            OXEN_LOG(err, "Failed to store message: {}", e.getErrorStr());
            throw;
        }
    }
    return true;
}


void Database::bulk_store(const std::vector<message_t>& items) {
    SQLite::Transaction t{impl->db};
    auto get_owner = impl->prepared_st(
            "SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto insert_owner = impl->prepared_st(
            "INSERT INTO owners (pubkey, type) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING id");
    std::unordered_map<user_pubkey_t, int64_t> seen;
    for (auto& m : items) {
        if (!m.pubkey)
            continue;
        if (auto [it, ins] = seen.emplace(m.pubkey, 0); ins) {
            auto ownerid = exec_and_maybe_get<int64_t>(get_owner, m.pubkey);
            get_owner->reset();
            if (!ownerid) {
                ownerid = exec_and_maybe_get<int64_t>(insert_owner, m.pubkey);
                insert_owner->reset();
            }
            if (ownerid)
                it->second = *ownerid;
            else {
                OXEN_LOG(err, "Failed to insert owner {} for bulk store", m.pubkey.prefixed_hex());
                seen.erase(it);
            }
        }
    }

    auto insert_message = impl->prepared_st(
            "INSERT INTO messages (owner, hash, timestamp, expiry, data) VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT DO NOTHING");

    for (auto& m : items) {
        if (!m.pubkey)
            continue;
        auto owner_it = seen.find(m.pubkey);
        if (owner_it == seen.end())
            continue;

        int foo =
        exec_query(insert_message,
                owner_it->second,
                m.hash,
                to_epoch_ms(m.timestamp),
                to_epoch_ms(m.expiry),
                blob_binder{m.data});
        insert_message->reset();
    }

    t.commit();
}

std::vector<message_t> Database::retrieve(
        const user_pubkey_t& pubkey,
        const std::string& last_hash,
        std::optional<int> num_results) {

    std::vector<message_t> results;

    auto owner_st = impl->prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto ownerid = exec_and_maybe_get<int64_t>(owner_st, pubkey);
    if (!ownerid)
        return results;

    std::optional<int64_t> last_id;
    if (!last_hash.empty()) {
        auto st = impl->prepared_st("SELECT id FROM messages WHERE owner = ? AND hash = ?");
        last_id = exec_and_maybe_get<int64_t>(st, *ownerid, last_hash);
    }

    auto st = impl->prepared_st(last_id
            ? "SELECT hash, timestamp, expiry, data FROM messages WHERE owner = ? AND id > ? ORDER BY id LIMIT ?"
            : "SELECT hash, timestamp, expiry, data FROM messages WHERE owner = ? ORDER BY id LIMIT ?");
    st->bind(1, *ownerid);
    if (last_id) st->bind(2, *last_id);
    st->bind(last_id ? 3 : 2, num_results.value_or(-1));

    while (st->executeStep()) {
        auto [hash, ts, exp, data] = get<std::string, int64_t, int64_t, std::string>(st);
        results.emplace_back(
                std::move(hash), from_epoch_ms(ts), from_epoch_ms(exp), std::move(data));
    }

    return results;
}

std::vector<message_t> Database::retrieve_all() {
    std::vector<message_t> results;
    auto st = impl->prepared_st("SELECT type, pubkey, hash, timestamp, expiry, data"
            " FROM owned_messages ORDER BY mid");

    while (st->executeStep()) {
        auto [type, pubkey, hash, ts, exp, data] =
            get<uint8_t, std::string, std::string, int64_t, int64_t, std::string>(st);
        results.emplace_back(
                impl->load_pubkey(type, pubkey),
                std::move(hash),
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }

    return results;
}

std::vector<std::string> Database::delete_all(const user_pubkey_t& pubkey) {
    auto st = impl->prepared_st(
            "DELETE FROM messages WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " RETURNING hash");
    return get_all<std::string>(st, pubkey);
}

static std::string multi_in_query(std::string_view prefix, size_t count, std::string_view suffix) {
    std::string query;
    query.reserve(prefix.size() + (count == 0 ? 0 : 2*count-1) + suffix.size());
    query += prefix;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) query += ',';
        query += '?';
    }
    query += suffix;
    return query;
}

std::vector<std::string> Database::delete_by_hash(
        const user_pubkey_t& pubkey, const std::vector<std::string>& msg_hashes) {
    if (msg_hashes.size() == 1) {
        // Use an optimized prepared statement for very common single-hash deletions
        auto st = impl->prepared_st("DELETE FROM messages"
                " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?) AND hash = ?"
                " RETURNING hash");
        return get_all<std::string>(st, pubkey, msg_hashes[0]);
    }

    SQLite::Statement st{impl->db, multi_in_query("DELETE FROM messages "
        "WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?) AND "
        "hash IN ("sv, // ?,?,?,...,?
        msg_hashes.size(),
        ") RETURNING hash"sv)};

    bind_pubkey(st, 1, 2, pubkey);
    for (size_t i = 0; i < msg_hashes.size(); i++)
        st.bindNoCopy(3 + i, msg_hashes[i]);
    return get_all<std::string>(st);
}

std::vector<std::string> Database::delete_by_timestamp(
        const user_pubkey_t& pubkey, std::chrono::system_clock::time_point timestamp) {
    auto st = impl->prepared_st("DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND timestamp <= ? RETURNING hash");
    return get_all<std::string>(st, pubkey, to_epoch_ms(timestamp));
}

std::vector<std::string>
Database::update_expiry(
        const user_pubkey_t& pubkey,
        const std::vector<std::string>& msg_hashes,
        std::chrono::system_clock::time_point new_exp) {

    auto new_exp_ms = to_epoch_ms(new_exp);

    if (msg_hashes.size() == 1) {
        // Pre-prepared version for the common single hash case
        auto st = impl->prepared_st("UPDATE messages SET expiry = ? "
                "WHERE expiry > ? AND hash = ?"
                " AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " RETURNING hash");
        return get_all<std::string>(st, new_exp_ms, new_exp_ms, msg_hashes[0], pubkey);
    }

    SQLite::Statement st{impl->db, multi_in_query("UPDATE messages SET expiry = ? "
        "WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?) "
        "AND hash IN ("sv, // ?,?,?,...,?
        msg_hashes.size(),
        ") RETURNING hash"sv)};
    st.bind(1, new_exp_ms);
    st.bind(2, new_exp_ms);
    bind_pubkey(st, 3, 4, pubkey);
    for (size_t i = 0; i < msg_hashes.size(); i++)
        st.bindNoCopy(5 + i, msg_hashes[i]);

    return get_all<std::string>(st);
}

std::vector<std::string>
Database::update_all_expiries(
        const user_pubkey_t& pubkey,
        std::chrono::system_clock::time_point new_exp
        ) {
    auto new_exp_ms = to_epoch_ms(new_exp);
    auto st = impl->prepared_st("UPDATE messages SET expiry = ? "
            "WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?) "
            "RETURNING hash");
    return get_all<std::string>(st, new_exp_ms, new_exp_ms, pubkey);
}

} // namespace oxen
