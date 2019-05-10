#pragma once

#include "Item.hpp"

#include <iostream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/asio.hpp>

struct sqlite3;
struct sqlite3_stmt;
class Timer;

class Database {
  public:
    Database(boost::asio::io_context& ioc, const std::string& db_path);
    ~Database();

    enum class DuplicateHandling { IGNORE, FAIL };

    bool store(const std::string& hash, const std::string& pubKey,
               const std::string& bytes, uint64_t ttl, uint64_t timestamp,
               const std::string& nonce,
               DuplicateHandling behaviour = DuplicateHandling::FAIL);

    bool bulk_store(const std::vector<service_node::storage::Item>& items);

    bool retrieve(const std::string& key,
                  std::vector<service_node::storage::Item>& items,
                  const std::string& lastHash);

    // Return the total number of messages stored
    bool get_message_count(uint64_t& count);

    // Get message with by `index` (must be smaller than the result of
    // `get_message_count`).
    bool retrieve_by_index(uint64_t index, service_node::storage::Item& item);

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
    sqlite3_stmt* delete_expired_stmt;

    boost::asio::steady_timer cleanup_timer_;
};
