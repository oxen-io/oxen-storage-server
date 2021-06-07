#pragma once

#include "Item.hpp"
#include "oxen_common.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
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

    // Deletes all messages owned by the given pubkey.  Returns the hashes of any deleted messages
    // on success (including the case where no messages are deleted), nullopt on query failure.
    std::optional<std::vector<std::string>> delete_all(std::string_view pubkey);

    // Delete a message owned by the given pubkey having the given hashes.  Returns the hashes of
    // any delete messages on success (including the case where no messages are deleted), nullopt on
    // query failure.
    std::optional<std::vector<std::string>> delete_by_hash(
            std::string_view pubkey, const std::vector<std::string_view>& msg_hashes);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp.  Returns the
    // hashes of any deleted messages (including the case where no messages are deleted), nullopt on
    // query failure.
    std::optional<std::vector<std::string>> delete_by_timestamp(
            std::string_view pubkey, std::chrono::system_clock::time_point timestamp);

    // Shortens the expiry time of the given messages owned by the given pubkey.  Expiries can only
    // be shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // [msgid, newexpiry] pairs indicating the new expiry of any messages found (note that the new
    // expiry may not have been updated if it was already shorter than the requested time).
    std::optional<std::vector<std::pair<std::string, std::chrono::system_clock::time_point>>>
    update_expiry(
            std::string_view pubkey,
            const std::vector<std::string_view>& msg_hashes,
            std::chrono::system_clock::time_point new_exp
            );

    // Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    // shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // [msg, newexpiry] for all messages, whether the expiry is updated or not.
    std::optional<std::vector<std::pair<std::string, std::chrono::system_clock::time_point>>>
    update_all_expiries(
            std::string_view pubkey, std::chrono::system_clock::time_point new_exp);

  private:
    struct sqlite_destructor {
        void operator()(sqlite3_stmt* ptr);
        void operator()(sqlite3* ptr);
    };

  public:
    using StatementPtr = std::unique_ptr<sqlite3_stmt, sqlite_destructor>;
    using SqlitePtr = std::unique_ptr<sqlite3, sqlite_destructor>;

  private:

    StatementPtr prepare_statement(std::string_view desc, std::string_view query);
    void open_and_prepare(const std::filesystem::path& db_path);

    // keep track of db full errorss so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

    SqlitePtr db;
    StatementPtr save_stmt;
    StatementPtr save_or_ignore_stmt;
    StatementPtr get_all_for_pk_stmt;
    StatementPtr get_all_stmt;
    StatementPtr get_stmt;
    StatementPtr get_row_count_stmt;
    StatementPtr get_random_stmt;
    StatementPtr get_by_hash_stmt;
    StatementPtr delete_expired_stmt;
    StatementPtr delete_by_timestamp_stmt;
    StatementPtr delete_all_stmt;
    StatementPtr update_all_expiries_stmt;
    StatementPtr page_count_stmt;
};

} // namespace oxen
