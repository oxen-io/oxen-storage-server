#include "Database.hpp"
#include "Timer.hpp"

#include "sqlite3.h"
#include <chrono>
#include <exception>

using namespace service_node::storage;

uint64_t get_time_ms() {
    const auto timestamp = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               timestamp.time_since_epoch())
        .count();
}

Database::~Database() {
    sqlite3_finalize(save_stmt);
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
    const auto now_ms = get_time_ms();

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
        "    `TimeReceived` INTEGER NOT NULL,"
        "    `TimeExpires` INTEGER NOT NULL,"
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

    save_stmt =
        prepare_statement("INSERT INTO Data "
                          "(Hash, Owner, TimeReceived, TimeExpires, Data)"
                          "VALUES (?,?,?,?,?);");
    if (!save_stmt)
        throw std::runtime_error("could not prepare the save statement");

    get_all_stmt = prepare_statement("SELECT * FROM Data WHERE `Owner` = ?;");
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
                     const std::string& bytes, uint64_t ttl) {
    const auto cur_time = get_time_ms();
    const auto exp_time = cur_time + (ttl * 1000);

    std::cout << pubKey << std::endl;
    std::cout << hash << std::endl;
    std::cout << ttl << std::endl;

    sqlite3_bind_text(save_stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(save_stmt, 2, pubKey.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(save_stmt, 3, cur_time);
    sqlite3_bind_int64(save_stmt, 4, exp_time);
    sqlite3_bind_blob(save_stmt, 5, bytes.data(), bytes.size(), SQLITE_STATIC);

    bool result = false;
    int rc;
    while (true) {
        rc = sqlite3_step(save_stmt);
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
    int reset_rc = sqlite3_reset(save_stmt);
    // If the most recent call to sqlite3_step(S) for the prepared statement S
    // indicated an error, then sqlite3_reset(S) returns an appropriate error
    // code.
    if (reset_rc != SQLITE_OK && reset_rc != rc) {
        throw new std::logic_error(
            "could not reset statement: unexpected value");
    }
    return result;
}

bool Database::retrieve(const std::string& pubKey, std::vector<Item>& items,
                        const std::string& lastHash) {

    sqlite3_stmt* stmt;

    if (lastHash.empty()) {
        stmt = get_all_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
    } else {
        stmt = get_stmt;
        sqlite3_bind_text(stmt, 1, pubKey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, lastHash.c_str(), -1, SQLITE_STATIC);
    }

    std::vector<std::string> results;
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
        const auto time_saved = sqlite3_column_int64(stmt, 2);
        const auto time_expires = sqlite3_column_int64(stmt, 3);
        const std::string bytes((char*)sqlite3_column_blob(stmt, 4),
                                sqlite3_column_bytes(stmt, 4));
        items.emplace_back(hash, pubKey, time_saved, time_expires, bytes);
    }

    int rc = sqlite3_reset(stmt);
    if (rc != SQLITE_OK) {
        return false;
    }
    return true;
}

bool Database::save_pushed() {}
