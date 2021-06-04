#pragma once

#include "Item.hpp"
#include "oxen_common.h"

#include <atomic>
#include <chrono>
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

    bool store(std::string_view hash, std::string_view pubKey, std::string_view bytes,
            std::chrono::system_clock::time_point timestamp, std::chrono::system_clock::time_point expiry,
            DuplicateHandling behaviour = DuplicateHandling::FAIL);

    bool store(const storage::Item& item, DuplicateHandling behaviour = DuplicateHandling::FAIL) {
        return store(item.hash, item.pub_key, item.data, item.timestamp, item.expiration, behaviour);
    }
    bool store(const message_t& msg, DuplicateHandling behaviour = DuplicateHandling::FAIL) {
        return store(msg.hash, msg.pub_key, msg.data, msg.timestamp, msg.expiry, behaviour);
    }

    bool bulk_store(const std::vector<storage::Item>& items);

    bool retrieve(const std::string& key, std::vector<storage::Item>& items,
                  const std::string& lastHash, int num_results = -1);

    // Returns the number of used database pages
    bool get_used_pages(uint64_t& count);

    // Return the total number of messages stored
    bool get_message_count(uint64_t& count);

    // Get random message. Returns false if there are no messages (or the db query failed)
    bool retrieve_random(storage::Item& item);

    // Get message by `msg_hash`, return true if found
    bool retrieve_by_hash(std::string_view msg_hash, storage::Item& item);

    // Removes expired messages from the database; the Database owner should call this periodically.
    void clean_expired();

    // Deletes all messages owned by the given pubkey.  Returns the number of deleted messages on
    // success, -1 on failure.
    int delete_all(std::string_view pubkey);

    // Delete a message owned by the given pubkey having the given hash.  Returns true if deleted.
    bool delete_by_hash(std::string_view pubkey, std::string_view msg_hash);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp.  Returns the
    // number of deleted messages.
    int delete_by_timestamp(std::string_view pubkey, uint64_t timestamp);

    // Updates the expiry time of a message owned by the given pubkey.  Expiries can only be
    // shortened (i.e. brought closer to now), not extended into the future.  Returns the new
    // message expiry timestamp, if found (note that the new expiry may not have been updated if it
    // was already shorter than the requested time).
    uint64_t update_expiry(std::string_view pubkey, std::string_view msg_hash);

  private:
    sqlite3_stmt* prepare_statement(const std::string& query);
    void open_and_prepare(const std::filesystem::path& db_path);

    // keep track of db full errorss so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

    sqlite3* db;
    sqlite3_stmt* save_stmt;
    sqlite3_stmt* save_or_ignore_stmt;
    sqlite3_stmt* get_all_for_pk_stmt;
    sqlite3_stmt* get_all_stmt;
    sqlite3_stmt* get_stmt;
    sqlite3_stmt* get_row_count_stmt;
    sqlite3_stmt* get_random_stmt;
    sqlite3_stmt* get_by_hash_stmt;
    sqlite3_stmt* delete_expired_stmt;
    sqlite3_stmt* page_count_stmt;
};

} // namespace oxen
