#pragma once

#include <oxenss/common/subaccount_token.h>
#include <oxenss/common/message.h>
#include <oxenss/common/pubkey.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stack>
#include <string>
#include <vector>

namespace oxenss {

using namespace std::literals;

class DatabaseImpl;
class LockedDBImpl;

/// Possible return values of a `store()`:
enum class StoreResult {
    New,       // Message did not exist and was inserted.
    Extended,  // Message existed, but the expiry was extended to match the stored timestamp.
    Exists,    // Message exists and already has an expiry >= the stored one.
    Full,      // Can't insert right now because the database is full.
};

// Storage database class.
class Database {
    std::stack<std::unique_ptr<DatabaseImpl>> impl_pool_;
    friend class DatabaseImpl;
    friend class LockedDBImpl;
    std::mutex impl_lock_;
    LockedDBImpl get_impl();

    const std::filesystem::path db_path_;

    friend class TestSuiteHacks;
    void test_suite_block_for(std::chrono::milliseconds duration);

    // keep track of db full errors so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

  public:
    // Recommended period for calling clean_expired()
    static constexpr auto CLEANUP_PERIOD = 10s;

    static constexpr int64_t SIZE_LIMIT = int64_t(3584) * 1024 * 1024;  // 3.5 GB

    // Constructor.  Note that you *must* also set up a timer that runs periodically (every
    // CLEANUP_PERIOD is recommended) and calls clean_expired().
    explicit Database(std::filesystem::path db_path);

    ~Database();

    // if the database is full then print an error only once ever N errors
    static constexpr int DB_FULL_FREQUENCY = 100;

    // Stores a message in the database.  Returns an enum value indicating the result -- see
    // StoreResult for a description.
    StoreResult store(const message& msg);

    void bulk_store(const std::vector<message>& items);

    // Default value for message overhead calculations in `retrieve`.  In practice, overhead for the
    // message itself (i.e. the json keys, etc.) seems to be in the 75-80 character range (depending
    // on whether json or bt-encoded), not including the hash + the data.
    constexpr static size_t DEFAULT_MSG_OVERHEAD = 100;

    // Retrieves messages owned by pubkey received since `last_hash` stored in namespace `ns`.  If
    // last_hash is empty or not found then returns all messages (up to the limit). Optionally takes
    // a maximum number of messages to return or a maximum aggregate size of messages to return.
    //
    // Note that the `pubkey` value of the returned message's will be left default constructed,
    // i.e. *not* filled with the given pubkey.
    //
    // Returns a vector of messages, and a bool indicating whether there are more results to
    // retrieve.
    std::pair<std::vector<message>, bool> retrieve(
            const user_pubkey& pubkey,
            namespace_id ns,
            const std::string& last_hash,
            std::optional<size_t> num_results = std::nullopt,
            std::optional<size_t> max_size = std::nullopt,
            bool size_b64 =
                    true,  // True if the data will get b64-encoded (and thus is 4/3 as large)
            size_t per_message_overhead =
                    DEFAULT_MSG_OVERHEAD  // how much overhead per message to allow for
    );

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

    // Get message by `msg_hash`, return true if found.  Note that this does *not* filter by
    // pubkey or namespace!
    std::optional<message> retrieve_by_hash(const std::string& msg_hash);

    // Removes expired messages from the database; the `Database` instance owner should call
    // this periodically.
    void clean_expired();

    // Deletes all messages owned by the given pubkey.  Returns the [namespace, hash] pairs of any
    // deleted messages.
    std::vector<std::pair<namespace_id, std::string>> delete_all(const user_pubkey& pubkey);

    // Deletes all messages owned by the given pubkey with the given namespace.  Returns the hashes
    // of any deleted messages.
    std::vector<std::string> delete_all(const user_pubkey& pubkey, namespace_id ns);

    // Delete messages owned by the given pubkey having the given hashes.  Returns the hashes of any
    // deleted messages.
    std::vector<std::string> delete_by_hash(
            const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp.  Returns the
    // [namespace, hash] pairs of any deleted messages.
    std::vector<std::pair<namespace_id, std::string>> delete_by_timestamp(
            const user_pubkey& pubkey, std::chrono::system_clock::time_point timestamp);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp in the given
    // namespace.  Returns the hashes of any deleted messages.
    std::vector<std::string> delete_by_timestamp(
            const user_pubkey& pubkey,
            namespace_id ns,
            std::chrono::system_clock::time_point timestamp);

    // Adds access tokens to the revoked token database so that users may not longer use those
    // tokens to authenticate.
    void revoke_subaccounts(
            const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccount);

    // Removes access tokens from the revoked token database so that users may use those tokens to
    // authenticate (if currently revoked).  Returns the number of tokens that were found and
    // removed.
    int unrevoke_subaccounts(
            const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccount);

    // Checks if a subaccount token exists in the revoked subaccount database. Returns true if the
    // subaccount has been revoked, false otherwise.
    bool subaccount_revoked(const user_pubkey& pubkey, const subaccount_token& subaccount);

    // Updates the expiry time of the given messages owned by the given pubkey.  Returns a vector of
    // hashes of updated messages (i.e. hashes that don't exist, or were not updated, are not
    // returned).
    //
    // extend_only and shorten_only allow message expiries to only be adjusted in one way or the
    // other.  They are mutually exclusive.
    std::vector<std::string> update_expiry(
            const user_pubkey& pubkey,
            const std::vector<std::string>& msg_hashes,
            std::chrono::system_clock::time_point new_exp,
            bool extend_only = false,
            bool shorten_only = false);

    // Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    // shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // [namespace, hash] pairs of messages that had their expiries shortened.
    std::vector<std::pair<namespace_id, std::string>> update_all_expiries(
            const user_pubkey& pubkey, std::chrono::system_clock::time_point new_exp);

    // Shortens the expiry time of all messages owned by the given pubkey in the given namespace.
    // Expiries can only be shortened (i.e. brought closer to now), not extended into the future.
    // Returns a vector of hashes of messages that had their expiries shortened.
    std::vector<std::string> update_all_expiries(
            const user_pubkey& pubkey,
            namespace_id ns,
            std::chrono::system_clock::time_point new_exp);

    // Retrieves the expiries of messages by hash.  Returns a map of hash -> expiry (hashes not
    // found are not included).
    std::map<std::string, int64_t> get_expiries(
            const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes);
};

}  // namespace oxenss
