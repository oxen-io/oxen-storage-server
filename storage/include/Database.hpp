#pragma once

#include "Item.hpp"

#include <iostream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;
class Timer;

class Database {
  public:
    Database(const std::string& db_path);
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
    sqlite3_stmt* delete_expired_stmt;

    std::unique_ptr<Timer> cleanup_timer;
};
