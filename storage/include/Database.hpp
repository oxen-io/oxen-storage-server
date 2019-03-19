#pragma once

#include "Item.hpp"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>
#include <iostream>

struct sqlite3;
struct sqlite3_stmt;
class Timer;

class Database {
  public:
    Database(const std::string& db_path);
    ~Database();

    /// this is low-level logic (separate?)
    bool store(const std::string& hash, const std::string& pubKey,
               const std::string& bytes, uint64_t ttl);
    bool retrieve(const std::string& key,
                  std::vector<service_node::storage::Item>& items,
                  const std::string& lastHash);

    /// this is high-level logic
    bool save_pushed();

  private:
    sqlite3_stmt* prepare_statement(const std::string& query);
    void open_and_prepare(const std::string& db_path);
    void perform_cleanup();

  private:
    sqlite3* db;
    sqlite3_stmt* save_stmt;
    sqlite3_stmt* get_all_stmt;
    sqlite3_stmt* get_stmt;
    sqlite3_stmt* delete_expired_stmt;

    std::unique_ptr<Timer> cleanup_timer;
};
