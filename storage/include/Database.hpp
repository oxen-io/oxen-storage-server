#pragma once

#include "Item.hpp"
#include "oxen_common.h"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace oxen {

// Storage database class.
class Database {
  public:
    // Recommended period for calling clean_expired()
    inline static constexpr auto CLEANUP_PERIOD = 10s;

    inline static constexpr int64_t PAGE_SIZE = 4096;
    inline static constexpr int64_t SIZE_LIMIT = int64_t(3584) * 1024 * 1024; // 3.5 GB
    inline static constexpr int64_t PAGE_LIMIT = SIZE_LIMIT / PAGE_SIZE;

    // Constructor.  Note that you *must* also set up a timer that runs periodically (every
    // CLEANUP_PERIOD is recommended) and calls clean_expired().
    explicit Database(const std::filesystem::path& db_path);
    ~Database();

    enum class DuplicateHandling { IGNORE, FAIL };

    bool store(const std::string& hash, const std::string& pubKey,
               const std::string& bytes, uint64_t ttl, uint64_t timestamp,
               const std::string& nonce,
               DuplicateHandling behaviour = DuplicateHandling::FAIL);

    bool bulk_store(const std::vector<storage::Item>& items);

    bool retrieve(const std::string& key, std::vector<storage::Item>& items,
                  const std::string& lastHash, int num_results = -1);

    // Returns the number of used database pages
    bool get_used_pages(uint64_t& count);

    // Return the total number of messages stored
    bool get_message_count(uint64_t& count);

    // Get message by `index` (must be smaller than the result of
    // `get_message_count`).
    bool retrieve_by_index(uint64_t index, storage::Item& item);

    // Get message by `msg_hash`, return true if found
    bool retrieve_by_hash(const std::string& msg_hash, storage::Item& item);

    // Removes expired messages from the database; the Database owner should call this periodically.
    void clean_expired();

  private:
    sqlite3_stmt* prepare_statement(const std::string& query);
    void open_and_prepare(const std::filesystem::path& db_path);

    sqlite3* db;
    sqlite3_stmt* save_stmt;
    sqlite3_stmt* save_or_ignore_stmt;
    sqlite3_stmt* get_all_for_pk_stmt;
    sqlite3_stmt* get_all_stmt;
    sqlite3_stmt* get_stmt;
    sqlite3_stmt* get_row_count_stmt;
    sqlite3_stmt* get_by_index_stmt;
    sqlite3_stmt* get_by_hash_stmt;
    sqlite3_stmt* delete_expired_stmt;
    sqlite3_stmt* page_count_stmt;
};

} // namespace oxen
