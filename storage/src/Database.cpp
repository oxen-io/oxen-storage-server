#include "Database.hpp"
#include "Timer.hpp"
#include "utils.hpp"

#include "sqlite3.h"
#include <exception>

using namespace service_node::storage;

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

Database::Database(const std::string& db_path)
    : cleanup_timer(new Timer(std::bind(&Database::perform_cleanup, this))) {
    open_and_prepare(db_path);
    cleanup_timer->start();
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

    char** errMsg = nullptr;
    rc = sqlite3_exec(db, create_table_query, nullptr, nullptr, errMsg);
    if (rc) {
        printf("%s\n", *errMsg);
        sqlite3_free(errMsg);
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

    get_all_for_pk_stmt =
        prepare_statement("SELECT * FROM Data WHERE `Owner` = ?;");
    if (!get_all_for_pk_stmt)
        throw std::runtime_error(
            "could not prepare the get all for pk statement");

    get_all_stmt = prepare_statement("SELECT * FROM Data;");
    if (!get_all_stmt)
        throw std::runtime_error("could not prepare the get all statement");

    get_stmt = prepare_statement(
        "SELECT * FROM `Data` WHERE `Owner` == ? AND rowid >"
        "COALESCE((SELECT `rowid` FROM `Data` WHERE `Hash` = ?), 0);");
    if (!get_stmt)
        throw std::runtime_error("could not prepare get statement");

    delete_expired_stmt =
        prepare_statement("DELETE FROM `Data` WHERE `TimeExpires` <= ?");
    if (!delete_expired_stmt)
        throw std::runtime_error(
            "could not prepare 'delete expired' statement");
}

bool Database::store(const std::string& hash, const std::string& pubKey,
                     const std::string& bytes, uint64_t ttl, uint64_t timestamp,
                     const std::string& nonce, DuplicateHandling duplicateHandling) {

    const auto exp_time = timestamp + ttl;

    sqlite3_stmt* stmt = duplicateHandling == DuplicateHandling::IGNORE ? save_or_ignore_stmt : save_stmt;

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
            throw std::runtime_error("could not store into db");
        }
    }
    int reset_rc = sqlite3_reset(stmt);
    // If the most recent call to sqlite3_step(S) for the prepared statement S
    // indicated an error, then sqlite3_reset(S) returns an appropriate error
    // code.
    if (reset_rc != SQLITE_OK && reset_rc != rc) {
        throw new std::logic_error(
            "could not reset statement: unexpected value");
    }
    return result;
}

bool Database::bulk_store(const std::vector<service_node::storage::Item>& items) {
    char *errmsg = 0;
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &errmsg) != SQLITE_OK) {
        return false;
    }

    try {
        for (const auto& item : items) {
            store(item.hash, item.pub_key, item.data, item.ttl, item.timestamp, item.nonce, DuplicateHandling::IGNORE);
        }
    } catch(...) {
        fprintf(stderr, "Failed to store items during bulk operation");
    }

    if (sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, &errmsg) != SQLITE_OK)
        return false;

    return true;
}

bool Database::retrieve(const std::string& pubKey, std::vector<Item>& items,
                        const std::string& lastHash) {

    sqlite3_stmt* stmt;

    if (pubKey.empty()) {
        stmt = get_all_stmt;
    } else if (lastHash.empty()) {
        stmt = get_all_for_pk_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
    } else {
        stmt = get_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, lastHash.c_str(), -1, SQLITE_STATIC);
    }

    while (true) {
        int res = sqlite3_step(stmt);
        if (res == SQLITE_DONE)
            break;
        if (res != SQLITE_ROW)
            throw std::runtime_error("ERROR: SQL runtime error");
        const auto hash =
            std::string((const char*)sqlite3_column_text(stmt, 0));
        const auto pub_key =
            std::string((const char*)sqlite3_column_text(stmt, 1));
        const auto ttl = sqlite3_column_int64(stmt, 2);
        const auto timestamp = sqlite3_column_int64(stmt, 3);
        const auto time_expires = sqlite3_column_int64(stmt, 4);
        const auto nonce =
            std::string((const char*)sqlite3_column_text(stmt, 5));
        const auto bytes = std::string((char*)sqlite3_column_blob(stmt, 6),
                                       sqlite3_column_bytes(stmt, 6));
        items.emplace_back(hash, pub_key, timestamp, ttl, time_expires, nonce,
                           bytes);
    }

    int rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        return false;
    }
    return true;
}
