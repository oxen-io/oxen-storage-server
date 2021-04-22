#pragma once

#include "Item.hpp"
#include "oxen_common.h"

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

struct sqlite3;
struct sqlite3_stmt;

namespace oxen {

constexpr auto DB_CLEANUP_PERIOD = std::chrono::seconds(10);

class Database {
  public:
    Database(boost::asio::io_context& ioc, const std::string& db_path,
             std::chrono::milliseconds cleanup_period = DB_CLEANUP_PERIOD);
    ~Database();

    enum class DuplicateHandling { IGNORE, FAIL };

    bool store(const std::string& hash, const std::string& pubKey,
               const std::string& bytes, uint64_t ttl, uint64_t timestamp,
               const std::string& nonce,
               DuplicateHandling behaviour = DuplicateHandling::FAIL);

    bool bulk_store(const std::vector<storage::Item>& items);

    bool retrieve(const std::string& key, std::vector<storage::Item>& items,
                  const std::string& lastHash, int num_results = -1);

    // Return the total number of messages stored
    bool get_message_count(uint64_t& count);

    // Get message by `index` (must be smaller than the result of
    // `get_message_count`).
    bool retrieve_by_index(uint64_t index, storage::Item& item);

    // Get message by `msg_hash`, return true if found
    bool retrieve_by_hash(const std::string& msg_hash, storage::Item& item);

  private:
    sqlite3_stmt* prepare_statement(const std::string& query);
    void open_and_prepare(const std::string& db_path);
    void perform_cleanup();

  private:
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

    const std::chrono::milliseconds cleanup_period;
    boost::asio::steady_timer cleanup_timer_;
};

} // namespace oxen
