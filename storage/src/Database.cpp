#include "Database.hpp"
#include "loki_logger.h"
#include "utils.hpp"

#include "sqlite3.h"
#include <exception>

namespace loki {
using namespace storage;

constexpr auto CLEANUP_PERIOD = std::chrono::seconds(10);

Database::~Database() {
    sqlite3_finalize(save_stmt);
    sqlite3_finalize(save_or_ignore_stmt);
    sqlite3_finalize(get_all_for_pk_stmt);
    sqlite3_finalize(get_all_stmt);
    sqlite3_finalize(get_stmt);
    sqlite3_finalize(delete_expired_stmt);
    sqlite3_close(db);
    std::cerr << "~Database\n";
}

Database::Database(boost::asio::io_context& ioc, const std::string& db_path)
    : cleanup_timer_(ioc) {
    open_and_prepare(db_path);

    perform_cleanup();
}

void Database::perform_cleanup() {
    const auto now_ms = util::get_time_ms();

    sqlite3_bind_int64(delete_expired_stmt, 1, now_ms);

    int rc;
    while (true) {
        rc = sqlite3_step(delete_expired_stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            fprintf(stderr, "Can't delete expired messages: %s\n",
                    sqlite3_errmsg(db));
        }
    }
    int reset_rc = sqlite3_reset(delete_expired_stmt);
    // If the most recent call to sqlite3_step(S) for the prepared statement S
    // indicated an error, then sqlite3_reset(S) returns an appropriate error
    // code.
    if (reset_rc != SQLITE_OK && reset_rc != rc) {
        fprintf(stderr, "sql error: unexpected value from sqlite3_reset");
    }

    cleanup_timer_.expires_after(CLEANUP_PERIOD);
    cleanup_timer_.async_wait(std::bind(&Database::perform_cleanup, this));
}

sqlite3_stmt* Database::prepare_statement(const std::string& query) {
    const char* pzTest;
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, query.c_str(), query.length() + 1, &stmt,
                                &pzTest);
    if (rc != SQLITE_OK) {
        printf("ERROR: sql error: %s", pzTest);
    }
    return stmt;
}

void Database::open_and_prepare(const std::string& db_path) {
    const std::string file_path = db_path + "/storage.db";
    int rc = sqlite3_open_v2(file_path.c_str(), &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                 SQLITE_OPEN_FULLMUTEX,
                             NULL);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        // throw?
        return;
    }

    const char* create_table_query =
        "CREATE TABLE IF NOT EXISTS `Data`("
        "    `Hash` VARCHAR(128) NOT NULL,"
        "    `Owner` VARCHAR(256) NOT NULL,"
        "    `TTL` INTEGER NOT NULL,"
        "    `Timestamp` INTEGER NOT NULL,"
        "    `TimeExpires` INTEGER NOT NULL,"
        "    `Nonce` VARCHAR(128) NOT NULL,"
        "    `Data` BLOB"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS `idx_data_hash` ON `Data` (`Hash`);"
        "CREATE INDEX IF NOT EXISTS `idx_data_owner` on `Data` ('Owner');";

    char* errMsg = nullptr;
    rc = sqlite3_exec(db, create_table_query, nullptr, nullptr, &errMsg);
    if (rc) {
        if (errMsg) {
            printf("%s\n", errMsg);
            sqlite3_free(errMsg);
        }
        throw std::runtime_error("Can't create table");
    }

    save_stmt = prepare_statement(
        "INSERT INTO Data "
        "(Hash, Owner, TTL, Timestamp, TimeExpires, Nonce, Data)"
        "VALUES (?,?,?,?,?,?,?);");
    if (!save_stmt)
        throw std::runtime_error("could not prepare the save statement");

    save_or_ignore_stmt = prepare_statement(
        "INSERT OR IGNORE INTO Data "
        "(Hash, Owner, TTL, Timestamp, TimeExpires, Nonce, Data)"
        "VALUES (?,?,?,?,?,?,?)");
    if (!save_or_ignore_stmt)
        throw std::runtime_error("could not prepare the bulk save statement");

    get_all_for_pk_stmt = prepare_statement(
        "SELECT * FROM Data WHERE `Owner` = ? ORDER BY rowid LIMIT ?;");
    if (!get_all_for_pk_stmt)
        throw std::runtime_error(
            "could not prepare the get all for pk statement");

    get_all_stmt = prepare_statement("SELECT * FROM Data ORDER BY rowid;");
    if (!get_all_stmt)
        throw std::runtime_error("could not prepare the get all statement");

    get_stmt =
        prepare_statement("SELECT * FROM `Data` WHERE `Owner` == ? AND rowid >"
                          "COALESCE((SELECT `rowid` FROM `Data` WHERE `Hash` = "
                          "?), 0) ORDER BY rowid LIMIT ?;");
    if (!get_stmt)
        throw std::runtime_error("could not prepare get statement");

    get_row_count_stmt = prepare_statement("SELECT count(*) FROM `Data`;");
    if (!get_row_count_stmt)
        throw std::runtime_error("could not prepare row count statement");

    get_by_index_stmt = prepare_statement("SELECT * FROM `Data` LIMIT ?, 1;");
    if (!get_by_index_stmt)
        throw std::runtime_error("could not prepare get by index statement");

    get_by_hash_stmt =
        prepare_statement("SELECT * FROM `Data` WHERE `Hash` = ?;");
    if (!get_by_hash_stmt)
        throw std::runtime_error("could not prepare get by hash statement");

    delete_expired_stmt =
        prepare_statement("DELETE FROM `Data` WHERE `TimeExpires` <= ?");
    if (!delete_expired_stmt)
        throw std::runtime_error(
            "could not prepare 'delete expired' statement");
}

bool Database::get_message_count(uint64_t& count) {

    int rc;
    bool success = false;
    while (true) {
        rc = sqlite3_step(get_row_count_stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_DONE) {
            break;
        } else if (rc == SQLITE_ROW) {
            count = sqlite3_column_int64(get_row_count_stmt, 0);
            success = true;
        } else {
            LOKI_LOG(error, "Could not execute `count` db statement");
            break;
        }
    }

    rc = sqlite3_reset(get_by_index_stmt);
    if (rc != SQLITE_OK) {
        LOKI_LOG(error, "sqlite reset error: {}", rc);
        success = false;
    }

    return success;
}

/// Extract item from the result of a successfull select statement execution
static Item extract_item(sqlite3_stmt* stmt) {

    Item item;

    // "If the SQL statement does not currently point to a valid row, or if the
    // column index is out of range, the result is undefined"
    item.hash = std::string((const char*)sqlite3_column_text(stmt, 0));
    item.pub_key = std::string((const char*)sqlite3_column_text(stmt, 1));
    item.ttl = sqlite3_column_int64(stmt, 2);
    item.timestamp = sqlite3_column_int64(stmt, 3);
    item.expiration_timestamp = sqlite3_column_int64(stmt, 4);
    item.nonce = std::string((const char*)sqlite3_column_text(stmt, 5));
    item.data = std::string((char*)sqlite3_column_blob(stmt, 6),
                            sqlite3_column_bytes(stmt, 6));
    return item;
}

bool Database::retrieve_by_index(uint64_t index, Item& item) {

    sqlite3_bind_int64(get_by_index_stmt, 1, index);

    bool success = false;
    int rc;
    while (true) {
        rc = sqlite3_step(get_by_index_stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_DONE) {
            // Note that if the index is out of bounds, we will get here
            // returning an empty Item
            break;
        } else if (rc == SQLITE_ROW) {
            item = extract_item(get_by_index_stmt);
            success = true;
            break;
        } else {
            LOKI_LOG(error,
                     "Could not execute `retrieve by index` db statement");
            break;
        }
    }

    rc = sqlite3_reset(get_by_index_stmt);
    if (rc != SQLITE_OK) {
        LOKI_LOG(error, "sqlite reset error: {}", rc);
        success = false;
    }

    return success;
}

bool Database::retrieve_by_hash(const std::string& msg_hash, Item& item) {

    sqlite3_bind_text(get_by_hash_stmt, 1, msg_hash.c_str(), -1, SQLITE_STATIC);

    bool success = false;
    int rc;
    while (true) {
        rc = sqlite3_step(get_by_hash_stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_DONE) {
            break;
        } else if (rc == SQLITE_ROW) {
            item = extract_item(get_by_hash_stmt);
            success = true;
            break;
        } else {
            LOKI_LOG(
                error,
                "Could not execute `retrieve by hash` db statement, ec: {}",
                rc);
            break;
        }
    }

    rc = sqlite3_reset(get_by_hash_stmt);
    if (rc != SQLITE_OK) {
        LOKI_LOG(error, "sqlite reset error: {}", rc);
        success = false;
    }

    return success;
}

bool Database::store(const std::string& hash, const std::string& pubKey,
                     const std::string& bytes, uint64_t ttl, uint64_t timestamp,
                     const std::string& nonce,
                     DuplicateHandling duplicateHandling) {

    const auto exp_time = timestamp + ttl;

    sqlite3_stmt* stmt = duplicateHandling == DuplicateHandling::IGNORE
                             ? save_or_ignore_stmt
                             : save_stmt;

    // TODO: bind can return errors, handle them
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pubKey.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, ttl);
    sqlite3_bind_int64(stmt, 4, timestamp);
    sqlite3_bind_int64(stmt, 5, exp_time);
    sqlite3_bind_blob(stmt, 6, nonce.data(), nonce.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 7, bytes.data(), bytes.size(), SQLITE_STATIC);

    bool result = false;
    int rc;
    while (true) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_BUSY) {
            continue;
        } else if (rc == SQLITE_CONSTRAINT) {
            break;
        } else if (rc == SQLITE_DONE) {
            result = true;
            break;
        } else {
            LOKI_LOG(error, "Could not execute `store` db statement, ec: {}",
                     rc);
            break;
        }
    }

    rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        LOKI_LOG(error, "sqlite reset error: {}", rc);
    }
    return result;
}

bool Database::bulk_store(const std::vector<Item>& items) {
    char* errmsg = 0;
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &errmsg) !=
        SQLITE_OK) {
        return false;
    }

    try {
        for (const auto& item : items) {
            store(item.hash, item.pub_key, item.data, item.ttl, item.timestamp,
                  item.nonce, DuplicateHandling::IGNORE);
        }
    } catch (...) {
        fprintf(stderr, "Failed to store items during bulk operation");
    }

    if (sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, &errmsg) != SQLITE_OK)
        return false;

    return true;
}

bool Database::retrieve(const std::string& pubKey, std::vector<Item>& items,
                        const std::string& lastHash, int num_results) {

    sqlite3_stmt* stmt;

    if (pubKey.empty()) {
        stmt = get_all_stmt;
    } else if (lastHash.empty()) {
        stmt = get_all_for_pk_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, num_results);
    } else {
        stmt = get_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, lastHash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, num_results);
    }

    bool success = false;

    while (true) {
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            success = true;
            break;
        } else if (rc == SQLITE_ROW) {
            auto item = extract_item(stmt);
            items.push_back(std::move(item));
        } else {
            LOKI_LOG(error, "Could not execute `retrieve` db statement, ec: {}",
                     rc);
            break;
        }
    }

    int rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        LOKI_LOG(error, "sqlite reset error: {}", rc);
        success = false;
    }
    return success;
}

} // namespace loki
