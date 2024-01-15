#include "database.hpp"
#include "SQLiteCpp/Exception.h"
#include "SQLiteCpp/Statement.h"
#include "SQLiteCpp/Transaction.h"
#include "oxenss/logging/oxen_logger.h"
#include "oxenss/utils/string_utils.hpp"
#include "oxenss/utils/time.hpp"
#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <shared_mutex>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

namespace oxen {

static auto logcat = log::Cat("db");

constexpr std::chrono::milliseconds SQLite_busy_timeout = 3s;

namespace {
    template <typename T>
    constexpr bool is_cstr = false;
    template <size_t N>
    constexpr bool is_cstr<char[N]> = true;
    template <size_t N>
    constexpr bool is_cstr<const char[N]> = true;
    template <>
    [[maybe_unused]] inline constexpr bool is_cstr<char*> = true;
    template <>
    [[maybe_unused]] inline constexpr bool is_cstr<const char*> = true;

    // Simple wrapper class that can be used to bind a blob through the templated binding code
    // below. E.g. `exec_query(st, 100, 42, blob_binder{data})` binds the third parameter using
    // no-copy blob binding of the contained data.
    struct blob_binder {
        std::string_view data;
        explicit blob_binder(std::string_view d) : data{d} {}
        template <typename Char, typename = std::enable_if_t<sizeof(Char) == 1>>
        explicit blob_binder(const std::basic_string_view<Char>& d) :
                data{reinterpret_cast<const char*>(d.data()), d.size()} {}
    };

    // Binds a string_view as a no-copy blob at parameter index i.
    void bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob) {
        st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
    }

    // Called from exec_query and similar to bind statement parameters for immediate execution.
    // strings (and c strings) use no-copy binding; user_pubkey values use *two* sequential
    // binding slots for pubkey (first) and type (second); integer values are bound by value.
    // You can bind a blob (by reference, like strings) by passing `blob_binder{data}`.
    template <typename T>
    void bind_oneshot(SQLite::Statement& st, int& i, const T& val) {
        if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
            st.bindNoCopy(i++, val);
        else if constexpr (std::is_same_v<T, blob_binder>)
            bind_blob_ref(st, i++, val.data);
        else if constexpr (std::is_same_v<T, user_pubkey>) {
            bind_blob_ref(st, i++, val.raw());
            st.bind(i++, val.type());
        } else if constexpr (std::is_same_v<T, namespace_id>)
            st.bind(i++, static_cast<std::underlying_type_t<namespace_id>>(val));
        else
            st.bind(i++, val);
    }

    // Binds pubkey in a query such as `... WHERE pubkey = ? AND type = ?` into positions i
    // (pubkey) and j (type).  The user_pubkey reference must stay valid for the duration of
    // the statement.
    void bind_pubkey(SQLite::Statement& st, int i, int j, const user_pubkey& pk) {
        bind_blob_ref(st, i, pk.raw());
        st.bind(j, pk.type());
    }

    // Executes a query that does not expect results.  Optionally binds parameters, if provided.
    // Returns the number of affected rows; throws on error or if results are returned.
    template <typename... T>
    int exec_query(SQLite::Statement& st, const T&... bind) {
        [[maybe_unused]] int i = 1;
        (bind_oneshot(st, i, bind), ...);
        return st.exec();
    }

    // Same as above, but prepares a literal query on the fly for use with queries that are only
    // used once.
    template <typename... T>
    int exec_query(SQLite::Database& db, const char* query, const T&... bind) {
        SQLite::Statement st{db, query};
        return exec_query(st, bind...);
    }

    template <typename T, typename... More>
    struct first_type {
        using type = T;
    };
    template <typename... T>
    using first_type_t = typename first_type<T...>::type;

    template <typename... T>
    struct tuple_or_pair_impl {
        using type = std::tuple<T...>;
    };
    template <typename T1, typename T2>
    struct tuple_or_pair_impl<T1, T2> {
        using type = std::pair<T1, T2>;
    };

    // Converts a parameter pack T... into either a plain T (if singleton), a pair (if exactly 2),
    // or a tuple<T...>:
    template <typename... T>
    using type_or_tuple = std::conditional_t<
            sizeof...(T) == 1,
            first_type_t<T...>,
            typename tuple_or_pair_impl<T...>::type>;

    // We want to keep namespace_id as a type-safe integer, which requires some working around here
    // to get an int64_t out of the database and stuff it into a namespace_id; everything else we
    // pass through untouched.
    template <typename... T>
    constexpr bool contains_namespace_id = (... || std::is_same_v<T, namespace_id>);

    template <typename T>
    using db_source_type = std::conditional_t<std::is_same_v<T, namespace_id>, int64_t, T>;

    template <typename T>
    std::conditional_t<std::is_same_v<T, namespace_id>, namespace_id, T&> transform_db_source_impl(
            db_source_type<T>& source_val) {
        if constexpr (std::is_same_v<T, namespace_id>)
            return static_cast<namespace_id>(source_val);
        else
            return source_val;
    }

    template <typename... T, size_t... I>
    type_or_tuple<T...> transform_db_source(
            std::tuple<db_source_type<T>...>&& source, std::index_sequence<I...>) {
        return {std::move(transform_db_source_impl<T>(std::get<I>(source)))...};
    }

    // Retrieves a single row of values from the current state of a statement (i.e. after a
    // executeStep() call that is expecting a return value).  If `T...` is a single type then this
    // returns the single T value; if T... is two values you get back a pair, otherwise you get back
    // a tuple of values.
    template <typename... T>
    type_or_tuple<T...> get(SQLite::Statement& st) {
        if constexpr (contains_namespace_id<T...>) {
            return transform_db_source<T...>(
                    get<std::conditional_t<std::is_same_v<T, namespace_id>, int64_t, T>...>(st),
                    std::make_index_sequence<sizeof...(T)>{});
        } else {
            using TT = type_or_tuple<T...>;
            if constexpr (sizeof...(T) == 1)
                return static_cast<TT>(st.getColumn(0));
            else
                return st.getColumns<TT, sizeof...(T)>();
        }
    }

    // Steps a statement to completion that is expected to return at most one row, optionally
    // binding values into it (if provided).  Returns a filled out optional<T> (or
    // optional<std::tuple<T...>>) if a row was retrieved, otherwise a nullopt.  Throws if more
    // than one row is retrieved.
    template <typename... T, typename... Args>
    std::optional<type_or_tuple<T...>> exec_and_maybe_get(
            SQLite::Statement& st, const Args&... bind) {
        [[maybe_unused]] int i = 1;
        (bind_oneshot(st, i, bind), ...);
        std::optional<type_or_tuple<T...>> result;
        while (st.executeStep()) {
            if (result) {
                log::error(
                        logcat,
                        "Expected single-row result, got multiple rows from {}",
                        st.getQuery());
                throw std::runtime_error{"DB error: expected single-row result, got multiple rows"};
            }
            result = get<T...>(st);
        }
        return result;
    }

    // Executes a statement to completion that is expected to return exactly one row, optionally
    // binding values into it (if provided).  Returns a T or std::tuple<T...> (depending on
    // whether or not more than one T is provided) for the row.  Throws an exception if no rows
    // or more than one row are returned.
    template <typename... T, typename... Args>
    type_or_tuple<T...> exec_and_get(SQLite::Statement& st, const Args&... bind) {
        auto maybe_result = exec_and_maybe_get<T...>(st, bind...);
        if (!maybe_result) {
            log::error(logcat, "Expected single-row result, got no rows from {}", st.getQuery());
            throw std::runtime_error{"DB error: expected single-row result, got not rows"};
        }
        return *std::move(maybe_result);
    }

    // Executes a query to completion, collecting each row into a vector<T>, vector<pair<T1,T2>, or
    // vector<tuple<T...>>, depending on whether 1, 2, or more Ts are given.  Can optionally bind
    // before executing.
    template <typename... T, typename... Bind>
    std::vector<type_or_tuple<T...>> get_all(SQLite::Statement& st, const Bind&... bind) {
        [[maybe_unused]] int i = 1;
        (bind_oneshot(st, i, bind), ...);
        std::vector<type_or_tuple<T...>> results;
        while (st.executeStep())
            results.push_back(get<T...>(st));
        return results;
    }

    // Similar to get_all<K, V>, but returns a std::map<K, V> rather than a std::vector<pair<K, V>>.
    template <typename K, typename V, typename... Bind>
    std::map<K, V> get_map(SQLite::Statement& st, const Bind&... bind) {
        [[maybe_unused]] int i = 1;
        (bind_oneshot(st, i, bind), ...);
        std::map<K, V> results;
        while (st.executeStep())
            results[static_cast<K>(st.getColumn(0))] = static_cast<V>(st.getColumn(1));
        return results;
    }

}  // namespace

class DatabaseImpl {
  public:
    oxen::Database& parent;
    SQLite::Database db;

    // keep track of db full errorss so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

    // SQLiteCpp's statements are not thread-safe, so we prepare them thread-locally when needed
    std::unordered_map<std::thread::id, std::unordered_map<std::string, SQLite::Statement>>
            prepared_sts;
    std::shared_mutex prepared_sts_mutex;

    int page_size;

    DatabaseImpl(Database& parent, const std::filesystem::path& db_path) :
            parent{parent},
            db{db_path / std::filesystem::u8path("storage.db"),
               SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX,
               SQLite_busy_timeout.count()} {
        // Don't fail on these because we can still work even if they fail
        if (int rc = db.tryExec("PRAGMA journal_mode = WAL"); rc != SQLITE_OK)
            log::error(logcat, "Failed to set journal mode to WAL: {}", sqlite3_errstr(rc));

        if (int rc = db.tryExec("PRAGMA synchronous = NORMAL"); rc != SQLITE_OK)
            log::error(logcat, "Failed to set synchronous mode to NORMAL: {}", sqlite3_errstr(rc));

        if (int rc = db.tryExec("PRAGMA foreign_keys = ON"); rc != SQLITE_OK) {
            auto m = fmt::format(
                    "Failed to enable foreign keys constraints: {}", sqlite3_errstr(rc));
            log::critical(logcat, m);
            throw std::runtime_error{m};
        }
        int fk_enabled = db.execAndGet("PRAGMA foreign_keys").getInt();
        if (fk_enabled != 1) {
            log::critical(
                    logcat,
                    "Failed to enable foreign key constraints; perhaps this sqlite3 is "
                    "compiled without it?");
            throw std::runtime_error{"Foreign key support is required"};
        }

        page_size = db.execAndGet("PRAGMA page_size").getInt();
        // Would use a placeholder here, but sqlite3 apparently doesn't support them for
        // PRAGMAs.
        if (int rc = db.tryExec(
                    "PRAGMA max_page_count = " + std::to_string(Database::SIZE_LIMIT / page_size));
            rc != SQLITE_OK) {
            auto m = fmt::format("Failed to set max page count: {}", sqlite3_errstr(rc));
            log::critical(logcat, m);
            throw std::runtime_error{m};
        }

        if (!db.tableExists("owners")) {
            create_schema();
        }

        bool have_namespace = false;
        SQLite::Statement msg_cols{db, "PRAGMA main.table_info(messages)"};
        while (msg_cols.executeStep()) {
            auto [cid, name] = get<int64_t, std::string>(msg_cols);
            if (name == "namespace")
                have_namespace = true;
        }

        if (!have_namespace) {
            log::info(logcat, "Upgrading database schema: adding namespace column");
            db.exec(R"(
DROP INDEX IF EXISTS messages_owner;
DROP VIEW IF EXISTS owned_messages;
ALTER TABLE messages ADD COLUMN namespace INTEGER NOT NULL DEFAULT 0;
            )");
        }

        if (db.tableExists("revoked_subkeys")) {
            log::info(logcat, "Upgrading database schema: dropping revoked_subkeys");
            db.exec("DROP TABLE revoked_subkeys");
        }
        if (!db.tableExists("revoked_subaccounts")) {
            log::info(logcat, "Upgrading database schema: adding revoked_subaccounts");
            db.exec(R"(
CREATE TABLE revoked_subaccounts (
    owner INTEGER REFERENCES owners(id) ON DELETE CASCADE,
    token BLOB NOT NULL,
    timestamp INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5)*86400000 AS INTEGER)),

    PRIMARY Key(owner, token)
);

CREATE TRIGGER IF NOT EXISTS revoked_autoclean
    AFTER INSERT ON revoked_subaccounts WHEN (SELECT COUNT(*) FROM revoked_subaccounts WHERE owner = NEW.owner) > 50
    BEGIN
        DELETE FROM revoked_subaccounts
            WHERE owner = NEW.owner and token NOT IN (
                SELECT token FROM revoked_subaccounts
                WHERE owner = NEW.owner
                ORDER BY timestamp DESC LIMIT 50
        );
    END;
            )");
        }

        views_triggers_indices();

        log::info(logcat, "Database setup complete");
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
    namespace INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    expiry INTEGER NOT NULL,
    data BLOB NOT NULL,

    UNIQUE(hash)
);
        )");

        if (db.tableExists("Data")) {
            log::warning(logcat, "Old database schema detected; performing migration...");

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

            SQLite::Statement ins_owner{
                    db, "INSERT INTO owners (type, pubkey) VALUES (?, ?) RETURNING id"};

            std::unordered_map<std::string, int> owner_ids;
            SQLite::Statement old_owners{db, "SELECT DISTINCT Owner FROM Data"};
            while (old_owners.executeStep()) {
                int type;
                std::array<char, 32> pubkey;
                std::string old_owner = old_owners.getColumn(0);
                if (old_owner.size() == 66 && util::starts_with(old_owner, "05") &&
                    oxenc::is_hex(old_owner)) {
                    type = 5;
                    oxenc::from_hex(old_owner.begin() + 2, old_owner.end(), pubkey.begin());
                } else if (old_owner.size() == 64 && oxenc::is_hex(old_owner)) {
                    type = 0;
                    oxenc::from_hex(old_owner.begin(), old_owner.end(), pubkey.begin());
                } else {
                    log::warning(
                            logcat, "Found invalid owner pubkey '{}' during migration; ignoring");
                    continue;
                }

                int id = exec_and_get<int>(ins_owner, type, old_owner);
                ins_owner.reset();
                owner_ids.emplace(std::move(old_owner), id);
            }

            log::warning(
                    logcat, "Migrated {} owner pubkeys.  Migrating messages...", owner_ids.size());

            SQLite::Statement ins_msg{
                    db,
                    "INSERT INTO messages (hash, owner, timestamp, expiry, "
                    "data) VALUES (?, ?, ?, ?, ?)"};

            SQLite::Statement sel_msgs{
                    db,
                    "SELECT Hash, Owner, Timestamp, TimeExpires, Data FROM Data ORDER BY rowid"};
            int msgs = 0, bad_owners = 0;
            while (sel_msgs.executeStep()) {
                auto [hash, owner, ts, exp, data] =
                        get<const char*, const char*, int64_t, int64_t, std::string>(sel_msgs);
                auto it = owner_ids.find(owner);
                if (it == owner_ids.end()) {
                    bad_owners++;
                    continue;
                }
                exec_query(ins_msg, hash, it->second, ts, exp, data);
                ins_msg.reset();
                msgs++;
            }

            log::warning(
                    logcat,
                    "Migrated {} messages ({} invalid owner ids); dropping old Data table",
                    msgs,
                    bad_owners);

            db.exec("DROP TABLE Data");

            log::warning(logcat, "Data migration complete!");
        }

        transaction.commit();
    }

    void views_triggers_indices() {
        // We create these separate from the table because it makes upgrading easier (we can just
        // drop the indices/views that we want to recreate).

        SQLite::Transaction transaction{db};

        db.exec(R"(
CREATE TRIGGER IF NOT EXISTS owner_autoclean
    AFTER DELETE ON messages FOR EACH ROW WHEN NOT EXISTS (SELECT * FROM messages WHERE owner = old.owner)
    BEGIN
        DELETE FROM owners WHERE id = old.owner;
    END;

CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expiry);
CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner, namespace, timestamp);
CREATE INDEX IF NOT EXISTS messages_hash ON messages(hash);

CREATE VIEW IF NOT EXISTS owned_messages AS
    SELECT owners.id AS oid, type, pubkey, messages.id AS mid, hash, namespace, timestamp, expiry, data
    FROM messages JOIN owners ON messages.owner = owners.id;

DROP TRIGGER IF EXISTS owned_messages_insert;
DROP TRIGGER IF EXISTS owned_messages_upsert;
)");

        transaction.commit();
    }

    /** Wrapper around a SQLite::Statement that calls `tryReset()` on destruction of the
     * wrapper. */
    class StatementWrapper {
        SQLite::Statement& st;

      public:
        /// Whether we should reset on destruction; can be set to false if needed.
        bool reset_on_destruction = true;

        explicit StatementWrapper(SQLite::Statement& st) noexcept : st{st} {}
        ~StatementWrapper() noexcept {
            if (reset_on_destruction)
                st.tryReset();
        }
        SQLite::Statement& operator*() noexcept { return st; }
        SQLite::Statement* operator->() noexcept { return &st; }
        operator SQLite::Statement&() noexcept { return st; }
    };

    StatementWrapper prepared_st(const std::string& query) {
        std::unordered_map<std::string, SQLite::Statement>* sts;
        {
            std::shared_lock rlock{prepared_sts_mutex};
            if (auto it = prepared_sts.find(std::this_thread::get_id()); it != prepared_sts.end())
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

    user_pubkey load_pubkey(uint8_t type, std::string pk) { return {type, std::move(pk)}; }
};

Database::Database(const std::filesystem::path& db_path) :
        impl{std::make_unique<DatabaseImpl>(*this, db_path)} {
    clean_expired();
}

Database::~Database() = default;

void Database::clean_expired() {
    impl->prepared_exec(
            "DELETE FROM messages WHERE expiry <= ?",
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

static std::optional<message> get_message(DatabaseImpl& impl, SQLite::Statement& st) {
    std::optional<message> msg;
    while (st.executeStep()) {
        assert(!msg);
        auto [hash, otype, opubkey, ns, ts, exp, data] =
                get<std::string, uint8_t, std::string, namespace_id, int64_t, int64_t, std::string>(
                        st);
        msg.emplace(
                impl.load_pubkey(otype, std::move(opubkey)),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }
    return msg;
}

std::optional<message> Database::retrieve_random() {
    clean_expired();
    auto st = impl->prepared_st(
            "SELECT hash, type, pubkey, namespace, timestamp, expiry, data"
            " FROM owned_messages "
            " WHERE mid = (SELECT id FROM messages ORDER BY RANDOM() LIMIT 1)");
    return get_message(*impl, st);
}

std::optional<message> Database::retrieve_by_hash(const std::string& msg_hash) {
    auto st = impl->prepared_st(
            "SELECT hash, type, pubkey, namespace, timestamp, expiry, data"
            " FROM owned_messages WHERE hash = ?");
    st->bindNoCopy(1, msg_hash);
    return get_message(*impl, st);
}

StoreResult Database::store(const message& msg) {

    StoreResult ret;
    try {

        SQLite::Transaction transaction{impl->db};

        int64_t owner_id;
        if (auto maybe = exec_and_maybe_get<int64_t>(
                    impl->prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
                    msg.pubkey))
            owner_id = *maybe;
        else
            owner_id = impl->prepared_get<int64_t>(
                    "INSERT INTO owners (pubkey, type) VALUES (?, ?) RETURNING id", msg.pubkey);

        // When storing to a public namespace we clear anything there (except for a duplicate, to
        // avoid unnecessary storage churn).
        if (is_public_outbox_namespace(msg.msg_namespace)) {
            impl->prepared_exec(
                    "DELETE FROM messages"
                    " WHERE owner = ? AND namespace = ? AND hash != ?",
                    owner_id,
                    msg.msg_namespace,
                    msg.hash);
        }

        auto new_exp = to_epoch_ms(msg.expiry);

        if (auto existing = exec_and_maybe_get<int64_t, int64_t>(
                    impl->prepared_st("SELECT id, expiry FROM messages WHERE hash = ?"),
                    msg.hash)) {
            const auto& [id, exp] = *existing;
            if (exp < new_exp) {
                impl->prepared_exec("UPDATE messages SET expiry = ? WHERE id = ?", new_exp, id);
                ret = StoreResult::Extended;
            } else {
                ret = StoreResult::Exists;
            }
        } else {
            impl->prepared_exec(
                    "INSERT INTO messages (owner, hash, namespace, timestamp, expiry, data)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    owner_id,
                    msg.hash,
                    msg.msg_namespace,
                    to_epoch_ms(msg.timestamp),
                    to_epoch_ms(msg.expiry),
                    blob_binder{msg.data});
            ret = StoreResult::New;
        }

        transaction.commit();

    } catch (const SQLite::Exception& e) {
        if (e.getErrorCode() == SQLITE_FULL) {
            if (impl->db_full_counter++ % DB_FULL_FREQUENCY == 0)
                log::error(logcat, "Failed to store message: database is full");
            return StoreResult::Full;
        } else {
            log::critical(logcat, "Failed to store message: {}", e.getErrorStr());
            throw;
        }
    }
    return ret;
}

void Database::bulk_store(const std::vector<message>& items) {
    SQLite::Transaction t{impl->db};
    auto get_owner = impl->prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto insert_owner = impl->prepared_st(
            "INSERT INTO owners (pubkey, type) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING id");
    std::unordered_map<user_pubkey, int64_t> seen;
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
                log::error(
                        logcat,
                        "Failed to insert owner {} for bulk store",
                        m.pubkey.prefixed_hex());
                seen.erase(it);
            }
        }
    }

    auto insert_message = impl->prepared_st(
            "INSERT INTO messages (owner, hash, namespace, timestamp, expiry, data)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT DO NOTHING");

    for (auto& m : items) {
        if (!m.pubkey)
            continue;
        auto owner_it = seen.find(m.pubkey);
        if (owner_it == seen.end())
            continue;

        exec_query(
                insert_message,
                owner_it->second,
                m.hash,
                m.msg_namespace,
                to_epoch_ms(m.timestamp),
                to_epoch_ms(m.expiry),
                blob_binder{m.data});
        insert_message->reset();
    }

    t.commit();
}

std::pair<std::vector<message>, bool> Database::retrieve(
        const user_pubkey& pubkey,
        namespace_id ns,
        const std::string& last_hash,
        std::optional<size_t> max_results,
        std::optional<size_t> max_size,
        const bool size_b64,
        const size_t per_message_overhead) {

    auto owner_st = impl->prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto ownerid = exec_and_maybe_get<int64_t>(owner_st, pubkey);
    if (!ownerid)
        return {};

    if (max_results && *max_results < 1)
        max_results = 1;

    std::optional<int64_t> last_id;
    if (!last_hash.empty()) {
        auto st = impl->prepared_st(
                "SELECT id FROM messages WHERE owner = ? AND namespace = ? AND hash = ?");
        last_id = exec_and_maybe_get<int64_t>(st, *ownerid, to_int(ns), last_hash);
    }

    auto st = impl->prepared_st(
            last_id ? "SELECT hash, namespace, timestamp, expiry, data FROM messages "
                      "WHERE owner = ? AND namespace = ? AND id > ? ORDER BY id LIMIT ?"
                    : "SELECT hash, namespace, timestamp, expiry, data FROM messages "
                      "WHERE owner = ? AND namespace = ? ORDER BY id LIMIT ?");
    int pos = 1;
    st->bind(pos++, *ownerid);
    st->bind(pos++, to_int(ns));
    if (last_id)
        st->bind(pos++, *last_id);
    st->bind(pos++, max_results ? static_cast<int>(*max_results) + 1 : -1);

    std::pair<std::vector<message>, bool> result{};
    auto& [results, more] = result;

    size_t agg_size = 0;
    while (st->executeStep()) {
        auto [hash, ns, ts, exp, data] =
                get<std::string, namespace_id, int64_t, int64_t, std::string>(st);
        if (max_results && results.size() >= *max_results) {
            more = true;
            break;
        }
        if (max_size) {
            agg_size += per_message_overhead;
            agg_size += hash.size();
            agg_size += size_b64 ? data.size() * 4 / 3 : data.size();
            if (!results.empty() && agg_size > *max_size) {
                more = true;
                break;
            }
        }

        results.emplace_back(
                std::move(hash), ns, from_epoch_ms(ts), from_epoch_ms(exp), std::move(data));
    }

    return result;
}

std::vector<message> Database::retrieve_all() {
    std::vector<message> results;
    auto st = impl->prepared_st(
            "SELECT type, pubkey, hash, namespace, timestamp, expiry, data"
            " FROM owned_messages ORDER BY mid");

    while (st->executeStep()) {
        auto [type, pubkey, hash, ns, ts, exp, data] =
                get<uint8_t, std::string, std::string, namespace_id, int64_t, int64_t, std::string>(
                        st);
        results.emplace_back(
                impl->load_pubkey(type, pubkey),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }

    return results;
}

std::vector<std::pair<namespace_id, std::string>> Database::delete_all(const user_pubkey& pubkey) {
    auto st = impl->prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " RETURNING namespace, hash");
    return get_all<namespace_id, std::string>(st, pubkey);
}

std::vector<std::string> Database::delete_all(const user_pubkey& pubkey, namespace_id ns) {
    auto st = impl->prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, pubkey, ns);
}

namespace {
    std::string multi_in_query(std::string_view prefix, size_t count, std::string_view suffix) {
        std::string query;
        query.reserve(prefix.size() + (count == 0 ? 0 : 2 * count - 1) + suffix.size());
        query += prefix;
        for (size_t i = 0; i < count; i++) {
            if (i > 0)
                query += ',';
            query += '?';
        }
        query += suffix;
        return query;
    }
}  // namespace

std::vector<std::string> Database::delete_by_hash(
        const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes) {
    if (msg_hashes.size() == 1) {
        // Use an optimized prepared statement for very common single-hash deletions
        auto st = impl->prepared_st(
                "DELETE FROM messages"
                " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " AND hash = ?"
                " RETURNING hash");
        return get_all<std::string>(st, pubkey, msg_hashes[0]);
    }

    SQLite::Statement st{
            impl->db,
            multi_in_query(
                    "DELETE FROM messages"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND hash IN ("sv,  // ?,?,?,...,?
                    msg_hashes.size(),
                    ") RETURNING hash"sv)};

    bind_pubkey(st, 1, 2, pubkey);
    for (size_t i = 0; i < msg_hashes.size(); i++)
        st.bindNoCopy(3 + i, msg_hashes[i]);
    return get_all<std::string>(st);
}

std::vector<std::pair<namespace_id, std::string>> Database::delete_by_timestamp(
        const user_pubkey& pubkey, std::chrono::system_clock::time_point timestamp) {
    auto st = impl->prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND timestamp <= ?"
            " RETURNING hash");
    return get_all<namespace_id, std::string>(st, pubkey, to_epoch_ms(timestamp));
}

std::vector<std::string> Database::delete_by_timestamp(
        const user_pubkey& pubkey,
        namespace_id ns,
        std::chrono::system_clock::time_point timestamp) {
    auto st = impl->prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND timestamp <= ? AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, pubkey, to_epoch_ms(timestamp), ns);
}

static constexpr auto ins_revoke_prefix = "INSERT INTO revoked_subaccounts (owner, token) "sv;
static constexpr auto ins_revoke_suffix =
        " ON CONFLICT(owner, token) DO UPDATE SET timestamp = excluded.timestamp "
        "WHERE revoked_subaccounts.timestamp < excluded.timestamp"sv;

void Database::revoke_subaccounts(
        const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccounts) {
    if (subaccounts.empty())
        return;

    if (subaccounts.size() == 1) {
        auto insert_token = impl->prepared_st(fmt::format(
                "{} VALUES ((SELECT id FROM owners WHERE pubkey = ? AND type = ?), ?) {}",
                ins_revoke_prefix,
                ins_revoke_suffix));
        exec_query(insert_token, pubkey, blob_binder{subaccounts[0].view()});
        return;
    }

    SQLite::Transaction transaction{impl->db};

    auto get_owner = impl->prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto ownerid = exec_and_maybe_get<int64_t>(get_owner, pubkey);
    if (!ownerid)
        return;

    auto insert_token = impl->prepared_st(
            fmt::format("{} VALUES (?, ?) {}", ins_revoke_prefix, ins_revoke_suffix));

    for (const auto& sa : subaccounts) {
        exec_query(insert_token, *ownerid, blob_binder{sa.view()});
        insert_token->reset();
    }

    transaction.commit();
}

int Database::unrevoke_subaccounts(
        const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccounts) {
    if (subaccounts.empty())
        return 0;

    if (subaccounts.size() == 1) {
        auto remove_token = impl->prepared_st(
                "DELETE FROM revoked_subaccounts"
                " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " AND token = ?");
        return exec_query(remove_token, pubkey, blob_binder{subaccounts[0].view()});
    }

    SQLite::Statement st{
            impl->db,
            multi_in_query(
                    "DELETE FROM revoked_subaccounts"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND token IN ("sv,  // ?,?,?,...,?
                    subaccounts.size(),
                    ")"sv)};

    bind_pubkey(st, 1, 2, pubkey);
    for (size_t i = 0; i < subaccounts.size(); i++) {
        auto sa = subaccounts[i].sview();
        st.bindNoCopy(3 + i, static_cast<const void*>(sa.data()), sa.size());
    }

    return exec_query(st);
}

bool Database::subaccount_revoked(const user_pubkey& pubkey, const subaccount_token& subaccount) {
    auto count = exec_and_get<int64_t>(
            impl->prepared_st("SELECT COUNT(*) FROM revoked_subaccounts WHERE token = ? AND "
                              "owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"),
            blob_binder{subaccount.view()},
            pubkey);
    return count > 0;
}

std::vector<std::string> Database::update_expiry(
        const user_pubkey& pubkey,
        const std::vector<std::string>& msg_hashes,
        std::chrono::system_clock::time_point new_exp,
        bool extend_only,
        bool shorten_only) {
    auto new_exp_ms = to_epoch_ms(new_exp);

    auto expiry_constraint = extend_only  ? " AND expiry < ?1"s
                           : shorten_only ? " AND expiry > ?1"s
                                          : ""s;
    if (msg_hashes.size() == 1) {
        // Pre-prepared version for the common single hash case
        auto st = impl->prepared_st(
                "UPDATE messages SET expiry = ? WHERE hash = ?"s + expiry_constraint +
                " AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " RETURNING hash");
        return get_all<std::string>(st, new_exp_ms, msg_hashes[0], pubkey);
    }

    SQLite::Statement st{
            impl->db,
            multi_in_query(
                    "UPDATE messages SET expiry = ?"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"s +
                            expiry_constraint + " AND hash IN (",  // ?,?,?,...,?
                    msg_hashes.size(),
                    ") RETURNING hash"sv)};
    st.bind(1, new_exp_ms);
    bind_pubkey(st, 2, 3, pubkey);
    for (size_t i = 0; i < msg_hashes.size(); i++)
        st.bindNoCopy(4 + i, msg_hashes[i]);

    return get_all<std::string>(st);
}

std::map<std::string, int64_t> Database::get_expiries(
        const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes) {
    if (msg_hashes.size() == 1) {
        // Pre-prepared version for the common single hash case
        auto st = impl->prepared_st(
                "SELECT hash, expiry FROM messages WHERE hash = ?"
                " AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)");
        return get_map<std::string, int64_t>(st);
    }

    SQLite::Statement st{
            impl->db,
            multi_in_query(
                    "SELECT hash, expiry FROM messages"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND hash IN ("sv,  // ?,?,?,...,?
                    msg_hashes.size(),
                    ")"sv)};
    bind_pubkey(st, 1, 2, pubkey);
    for (size_t i = 0; i < msg_hashes.size(); i++)
        st.bindNoCopy(3 + i, msg_hashes[i]);

    return get_map<std::string, int64_t>(st);
}

std::vector<std::pair<namespace_id, std::string>> Database::update_all_expiries(
        const user_pubkey& pubkey, std::chrono::system_clock::time_point new_exp) {
    auto new_exp_ms = to_epoch_ms(new_exp);
    auto st = impl->prepared_st(
            "UPDATE messages SET expiry = ?"
            " WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " RETURNING namespace, hash");
    return get_all<namespace_id, std::string>(st, new_exp_ms, new_exp_ms, pubkey);
}

std::vector<std::string> Database::update_all_expiries(
        const user_pubkey& pubkey, namespace_id ns, std::chrono::system_clock::time_point new_exp) {
    auto new_exp_ms = to_epoch_ms(new_exp);
    auto st = impl->prepared_st(
            "UPDATE messages SET expiry = ?"
            " WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, new_exp_ms, new_exp_ms, pubkey, ns);
}

}  // namespace oxen
