#include "Database.hpp"
#include "oxen_logger.h"
#include "utils.hpp"

#include "sqlite3.h"
#include <chrono>
#include <cstdlib>
#include <exception>

namespace oxen {
using namespace storage;

void Database::sqlite_destructor::operator()(sqlite3* ptr) {
    sqlite3_close(ptr);
}
void Database::sqlite_destructor::operator()(sqlite3_stmt* ptr) {
    sqlite3_finalize(ptr);
}

Database::Database(const std::filesystem::path& db_path) {
    open_and_prepare(db_path);

    clean_expired();
}

void Database::clean_expired() {
    using namespace std::chrono;
    auto* stmt = delete_expired_stmt.get();
    sqlite3_bind_int64(stmt, 1, duration_cast<milliseconds>(
                system_clock::now().time_since_epoch()).count());

    int rc;
    while (true) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            OXEN_LOG(err, "Can't delete expired messages: {}", sqlite3_errmsg(db.get()));
        }
    }
    int reset_rc = sqlite3_reset(stmt);
    // If the most recent call to sqlite3_step(S) for the prepared statement S
    // indicated an error, then sqlite3_reset(S) returns an appropriate error
    // code.
    if (reset_rc != SQLITE_OK && reset_rc != rc) {
        OXEN_LOG(err, "sql error: unexpected value from sqlite3_reset");
    }
}

Database::StatementPtr Database::prepare_statement(std::string_view desc, const std::string& query) {
    sqlite3_stmt* s = nullptr;
    int rc = sqlite3_prepare_v2(db.get(), query.c_str(), query.length() + 1, &s, nullptr);
    StatementPtr stmt{s};
    if (rc != SQLITE_OK) {
        OXEN_LOG(err, "sql error compiling {}: {}", desc, sqlite3_errstr(rc));
        throw std::runtime_error{"could not prepare '" + std::string{desc} + "' statement"};
    }
    return stmt;
}

static void set_page_count(sqlite3* db) {

    char* errMsg = nullptr;

    auto cb = [](void* a_param, int argc, char** argv, char** column) -> int {
        if (argc == 0) {
            OXEN_LOG(err, "Failed to set the page count limit");
            return 0;
        }

        int res = strtol(argv[0], NULL, 10);

        if (res == 0) {
            OXEN_LOG(err, "Failed to convert page limit ({}) to a number",
                     argv[0]);
            return 0;
        }

        OXEN_LOG(info, "DB page limit is set to: {}", res);

        return 0;
    };

    int rc = sqlite3_exec(
        db, fmt::format("PRAGMA MAX_PAGE_COUNT = {};", Database::PAGE_LIMIT).c_str(),
        cb, nullptr, &errMsg);

    if (rc) {
        if (errMsg) {
            OXEN_LOG(err, "Query error: {}", errMsg);
        }
    }
}

static void check_page_size(sqlite3* db) {

    char* errMsg = nullptr;

    auto cb = [](void* a_param, int argc, char** argv, char** column) -> int {
        if (argc == 0) {
            OXEN_LOG(err, "Could not get DB page size");
        }

        int res = strtol(argv[0], NULL, 10);

        if (res == 0) {
            OXEN_LOG(err, "Failed to convert page size ({}) to a number",
                     argv[0]);
            return 0;
        }

        if (res != Database::PAGE_SIZE) {
            OXEN_LOG(warn, "Unexpected DB page size: {}", res);
        } else {
            OXEN_LOG(info, "DB page size: {}", res);
        }

        return 0;
    };

    int rc = sqlite3_exec(db, "PRAGMA page_size;", cb, nullptr, &errMsg);
    if (rc) {
        if (errMsg) {
            OXEN_LOG(err, "Query error: {}", errMsg);
        }
    }
}

void Database::open_and_prepare(const std::filesystem::path& db_path) {
    const auto file_path = db_path / "storage.db";
    if (sqlite3* new_db; sqlite3_open_v2(
                file_path.u8string().c_str(), &new_db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nullptr) == SQLITE_OK)
        db = SqlitePtr{new_db};
    else {
        auto err = fmt::format("Can't open database: {}", sqlite3_errmsg(new_db));
        OXEN_LOG(critical, err);
        sqlite3_close(new_db);
        throw std::runtime_error{err};
    }

    // Don't fail on these because we can still work even if they fail
    if (int rc = sqlite3_exec(db.get(), "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
            rc != SQLITE_OK)
        OXEN_LOG(err, "Failed to set journal mode to WAL: {}", sqlite3_errstr(rc));

    if (int rc = sqlite3_exec(db.get(), "PRAGMA synchronous = NORMAL", nullptr, nullptr, nullptr);
            rc != SQLITE_OK)
        OXEN_LOG(err, "Failed to set synchronous mode to NORMAL: {}", sqlite3_errstr(rc));

    check_page_size(db.get());
    set_page_count(db.get());

    const char* create_table_query =
        "CREATE TABLE IF NOT EXISTS Data("
        "    Hash VARCHAR(128) NOT NULL,"
        "    Owner VARCHAR(256) NOT NULL,"
        "    TTL INTEGER NOT NULL," // No longer used; TODO: nuke this the next time we do a table migration
        "    Timestamp INTEGER NOT NULL,"
        "    TimeExpires INTEGER NOT NULL,"
        "    Nonce VARCHAR(128) NOT NULL," // No longer used; TODO: nuke this field the next time we do a table migration
        "    Data BLOB"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_data_hash ON Data(Hash);"
        "CREATE INDEX IF NOT EXISTS idx_data_owner on Data(Owner);";
    // TODO: WTF -- the above index was previously 'Owner' and so created an index on the FIXED LITERAL STRING 'Owner' for every row

    if (char* errMsg = nullptr;
            sqlite3_exec(db.get(), create_table_query, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        if (errMsg) {
            OXEN_LOG(err, "{}", errMsg);
            sqlite3_free(errMsg);
        }
        throw std::runtime_error("Can't create table");
    }

    save_stmt = prepare_statement("save", R"(
        INSERT INTO Data
        (Hash, Owner, Timestamp, TimeExpires, Data, TTL, Nonce)
        VALUES (?,?,?,?,?,0,''))");

    save_or_ignore_stmt = prepare_statement("bulk save", R"(
        INSERT OR IGNORE INTO Data
        (Hash, Owner, Timestamp, TimeExpires, Data, TTL, Nonce)
        VALUES (?,?,?,?,?,0,''))");

    get_all_for_pk_stmt = prepare_statement("get all for pk", R"(
        SELECT Hash, Owner, Timestamp, TimeExpires, Data
        FROM Data
        WHERE Owner = ?
        ORDER BY rowid LIMIT ?)");

    get_all_stmt = prepare_statement("get all", R"(
        SELECT Hash, Owner, Timestamp, TimeExpires, Data
        FROM Data
        ORDER BY rowid)");

    // FIXME: this query is cursed: rowid is not guaranteed to be monotonic, *nor* is it guaranteed
    // to even stay the same.  This table structure has to be redesigned.
    get_stmt = prepare_statement("get", R"(
        SELECT Hash, Owner, Timestamp, TimeExpires, Data
        FROM Data
        WHERE Owner = ? AND rowid > COALESCE((SELECT rowid FROM Data WHERE Hash = ?), 0)
        ORDER BY rowid
        LIMIT ?)");

    get_row_count_stmt = prepare_statement("row count", "SELECT COUNT(*) FROM Data");

    get_random_stmt = prepare_statement("get random", R"(
        SELECT Hash, Owner, Timestamp, TimeExpires, Data
        FROM Data
        WHERE rowid = (SELECT rowid FROM Data ORDER BY RANDOM() LIMIT 1))");

    get_by_hash_stmt = prepare_statement("get by hash", R"(
        SELECT Hash, Owner, Timestamp, TimeExpires, Data
        FROM Data
        WHERE Hash = ?)");

    delete_expired_stmt = prepare_statement(
            "delete expired", "DELETE FROM Data WHERE TimeExpires <= ?");

    page_count_stmt = prepare_statement("page count", "PRAGMA page_count");
}

// Gets results, calls a callback with the sqlite3_statement* to extract them.  Returns true if at
// least one row was fetched (and callback invoked), false otherwise.
template <typename Func>
static bool get_results(std::string_view desc, Database::SqlitePtr& db, Database::StatementPtr& stmt, Func callback) {
    int rc;
    bool success = false;
    while (true) {
        rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_BUSY)
            continue;
        else if (rc == SQLITE_DONE)
            break;
        else if (rc == SQLITE_ROW) {
            callback(stmt.get());
            success = true;
        } else {
            OXEN_LOG(critical, "Could not execute {} db statement", desc);
            break;
        }
    }

    rc = sqlite3_reset(stmt.get());
    if (rc != SQLITE_OK) {
        OXEN_LOG(critical, "sqlite reset error: [{}], {}", rc,
                 sqlite3_errmsg(db.get()));
        success = false;
    }
    return success;
}

bool Database::get_used_pages(uint64_t& count) {
    return get_results("page count", db, page_count_stmt, [&count](auto* stmt) {
        count = sqlite3_column_int64(stmt, 0);
    });
}

bool Database::get_message_count(uint64_t& count) {
    return get_results("message count", db, get_row_count_stmt, [&count](auto* stmt) {
        count = sqlite3_column_int64(stmt, 0);
    });
}

/// Extract item from the result of a successfull select statement execution
static Item extract_item(sqlite3_stmt* stmt) {
    using namespace std::chrono;
    Item item;
    item.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    item.pub_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    item.timestamp = system_clock::time_point{milliseconds{sqlite3_column_int64(stmt, 2)}};
    item.expiration = system_clock::time_point{milliseconds{sqlite3_column_int64(stmt, 3)}};
    item.data = std::string(reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 4)),
            sqlite3_column_bytes(stmt, 4));
    return item;
}

bool Database::retrieve_random(Item& item) {
    return get_results("random message", db, get_random_stmt, [&item](auto* stmt) {
        item = extract_item(stmt);
    });
}

bool Database::retrieve_by_hash(std::string_view msg_hash, Item& item) {

    sqlite3_bind_text(get_by_hash_stmt.get(), 1, msg_hash.data(), msg_hash.size(), SQLITE_STATIC);

    return get_results("retrieve by hash", db, get_by_hash_stmt, [&item](auto* stmt) {
        item = extract_item(stmt);
    });
}

bool Database::store(
        std::string_view hash,
        std::string_view pubKey,
        std::string_view bytes,
        std::chrono::system_clock::time_point timestamp,
        std::chrono::system_clock::time_point expiry,
        DuplicateHandling duplicateHandling) {

    auto& stmt = duplicateHandling == DuplicateHandling::IGNORE
        ? save_or_ignore_stmt
        : save_stmt;

    // TODO: bind can return errors, handle them
    auto* s = stmt.get();
    sqlite3_bind_text(s, 1, hash.data(), hash.size(), SQLITE_STATIC);
    sqlite3_bind_text(s, 2, pubKey.data(), pubKey.size(), SQLITE_STATIC);
    using namespace std::chrono;
    sqlite3_bind_int64(s, 3, duration_cast<milliseconds>(timestamp.time_since_epoch()).count());
    sqlite3_bind_int64(s, 4, duration_cast<milliseconds>(expiry.time_since_epoch()).count());
    sqlite3_bind_blob(s, 5, bytes.data(), bytes.size(), SQLITE_STATIC);

    // print the error once so many errors
    constexpr int DB_FULL_FREQUENCY = 100;

    bool result = false;
    int rc;
    while (true) {
        rc = sqlite3_step(s);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_CONSTRAINT) {
            break;
        } else if (rc == SQLITE_DONE) {
            result = true;
            break;
        } else if (rc == SQLITE_FULL) {
            if (db_full_counter++ % DB_FULL_FREQUENCY == 0) {
                OXEN_LOG(err, "Failed to store message: database is full");
            }
            break;
        } else {
            OXEN_LOG(critical, "Could not execute `store` db statement, ec: {}",
                     rc);
            break;
        }
    }

    rc = sqlite3_reset(s);
    if (rc != SQLITE_OK && rc != SQLITE_CONSTRAINT && rc != SQLITE_FULL) {
        OXEN_LOG(critical, "sqlite reset error: [{}], {}", rc,
                 sqlite3_errmsg(db.get()));
    }
    return result;
}

bool Database::bulk_store(const std::vector<Item>& items) {
    char* errmsg = 0;
    if (sqlite3_exec(db.get(), "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg) != SQLITE_OK)
        return false;

    try {
        for (const auto& item : items)
            store(item, DuplicateHandling::IGNORE);
    } catch (...) {
        OXEN_LOG(err, "Failed to store items during bulk operation");
    }

    if (sqlite3_exec(db.get(), "END TRANSACTION;", nullptr, nullptr, &errmsg) != SQLITE_OK)
        return false;

    return true;
}

bool Database::retrieve(const std::string& pubKey, std::vector<Item>& items,
                        const std::string& lastHash, int num_results) {

    StatementPtr* stmt;

    if (pubKey.empty()) {
        stmt = &get_all_stmt;
    } else if (lastHash.empty()) {
        stmt = &get_all_for_pk_stmt;
        sqlite3_bind_text(stmt->get(), 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt->get(), 2, num_results);
    } else {
        stmt = &get_stmt;
        sqlite3_bind_text(stmt->get(), 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt->get(), 2, lastHash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt->get(), 3, num_results);
    }

    return get_results("retrieve", db, get_by_hash_stmt, [&items](auto* stmt) {
        items.push_back(extract_item(stmt));
    });
}

} // namespace oxen
