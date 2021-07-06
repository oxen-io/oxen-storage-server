#pragma once

#include "oxen_common.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace oxen {

class DatabaseImpl;

// Storage database class.
class Database {
    std::unique_ptr<DatabaseImpl> impl;
    friend class DatabaseImpl;

  public:
    // Recommended period for calling clean_expired()
    inline static constexpr auto CLEANUP_PERIOD = 10s;

    inline static constexpr int64_t SIZE_LIMIT = int64_t(3584) * 1024 * 1024; // 3.5 GB

    // Constructor.  Note that you *must* also set up a timer that runs periodically (every
    // CLEANUP_PERIOD is recommended) and calls clean_expired().
    explicit Database(const std::filesystem::path& db_path);

    ~Database();

    // if the database is full then print an error only once ever N errors
    inline static constexpr int DB_FULL_FREQUENCY = 100;

    // Attempts to store a message in the database.  Returns true if inserted, false on failure due
    // to the message already existing, and nullopt if the insertion failed because the database
    // is full.  For other query failures, throws.
    // 
    // This means `if (db.store(...))` will be true if inserted *or* already present; to check only
    // for insertion use `ins && *ins`.
    std::optional<bool> store(const message& msg);

    void bulk_store(const std::vector<message>& items);

    // Retrieves messages owned by pubkey received since `last_hash` (which must also be owned by
    // pubkey).  If last_hash is empty or not found then returns all messages (up to the limit).
    // Optionally takes a maximum number of messages to return.
    //
    // Note that the `pubkey` value of the returned message's will be left default constructed,
    // i.e. *not* filled with the given pubkey.
    std::vector<message> retrieve(
            const user_pubkey_t& pubkey,
            const std::string& last_hash,
            std::optional<int> num_results = std::nullopt);

    // Retrieves all messages.
    std::vector<message> retrieve_all();

    // Return the total number of messages stored
    int64_t get_message_count();

    // Returns the number of distinct owner pubkeys with stored messages
    int64_t get_owner_count();

    // Returns the number of used bytes (i.e. used pages * page size) of the database
    int64_t get_used_bytes();

    // Get random message. Returns nullopt if there are no messages.
    std::optional<message> retrieve_random();

    // Get message by `msg_hash`, return true if found.  Note that this does *not* filter by pubkey!
    std::optional<message> retrieve_by_hash(const std::string& msg_hash);

    // Removes expired messages from the database; the `Database` instance owner should call this
    // periodically.
    void clean_expired();

    // Deletes all messages owned by the given pubkey.  Returns the hashes of any deleted messages
    // on success (including the case where no messages are deleted), nullopt on query failure.
    std::vector<std::string> delete_all(const user_pubkey_t& pubkey);

    // Delete a message owned by the given pubkey having the given hashes.  Returns the hashes of
    // any delete messages on success (including the case where no messages are deleted), nullopt on
    // query failure.
    std::vector<std::string> delete_by_hash(
            const user_pubkey_t& pubkey, const std::vector<std::string>& msg_hashes);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp.  Returns the
    // hashes of any deleted messages (including the case where no messages are deleted), nullopt on
    // query failure.
    std::vector<std::string> delete_by_timestamp(
            const user_pubkey_t& pubkey, std::chrono::system_clock::time_point timestamp);

    // Shortens the expiry time of the given messages owned by the given pubkey.  Expiries can only
    // be shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // hashes of messages that had their expiries updates.  (Missing messages and messages that
    // already had an expiry <= the given expiry value are not returned).
    std::vector<std::string> update_expiry(
            const user_pubkey_t& pubkey,
            const std::vector<std::string>& msg_hashes,
            std::chrono::system_clock::time_point new_exp
            );

    // Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    // shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // hashes of messages that had their expiries shorten.
    std::vector<std::string> update_all_expiries(
            const user_pubkey_t& pubkey, std::chrono::system_clock::time_point new_exp);
};

} // namespace oxen
