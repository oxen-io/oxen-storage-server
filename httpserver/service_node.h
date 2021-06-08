#pragma once

#include <chrono>
#include <forward_list>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "Database.hpp"
#include "oxen_common.h"
#include "oxend_key.h"
#include "reachability_testing.h"
#include "stats.h"
#include "swarm.h"

namespace oxen {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;

// How long we wait for a HTTPS or OMQ ping response from another SN when ping testing
inline constexpr auto SN_PING_TIMEOUT = 5s;

// How long we wait for a storage test response (HTTPS until HF19, then OMQ)
inline constexpr auto STORAGE_TEST_TIMEOUT = 15s;

// Timeout for bootstrap node OMQ requests
inline constexpr auto BOOTSTRAP_TIMEOUT = 10s;

// The earliest hardfork *this* version of storage server will work on:
inline constexpr int STORAGE_SERVER_HARDFORK = 18;
// HF at which we switch to /ping_test/v1 instead of /swarms/ping_test/v1 for HTTPS pings
inline constexpr int HARDFORK_HTTPS_PING_TEST_URL = 19;
// HF at which we switch to OMQ storage tests instead of HTTPS
inline constexpr int HARDFORK_OMQ_STORAGE_TESTS = 19;

namespace storage {
struct Item;
} // namespace storage

class OxenmqServer;
struct OnionRequestMetadata;
struct oxend_key_pair_t;
class Swarm;
struct signature;
struct Response;

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

/// All service node logic that is not network-specific
class ServiceNode {
    bool syncing_ = true;
    bool active_ = false;
    bool got_first_response_ = false;
    bool force_start_ = false;
    std::atomic<bool> shutting_down_ = false;
    int hardfork_ = 0;
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    std::string block_hash_;
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const sn_record_t our_address_;
    const legacy_seckey our_seckey_;

    /// Cache for block_height/block_hash mapping
    std::map<uint64_t, std::string> block_hashes_cache_;

    // Need to make sure we only use this to get OxenMQ object and
    // not call any method that would in turn call a method in SN
    // causing a deadlock
    OxenmqServer& omq_server_;

    std::atomic<int> oxend_pings_ = 0; // Consecutive successful pings, used for batching logs about it

    // Will be set to true while we have an outstanding update_swarms() call so that we squelch
    // other update_swarms() until it finishes (or fails), to avoid spamming oxend (particularly
    // when syncing when we get tons of block notifications quickly).
    std::atomic<bool> updating_swarms_ = false;

    reachability_testing reach_records_;

    mutable all_stats_t all_stats_;

    mutable std::recursive_mutex sn_mutex_;

    std::forward_list<std::future<void>> outstanding_https_reqs_;

    // Save multiple items to the database at once (i.e. in a single transaction)
    void save_bulk(const std::vector<storage::Item>& items);

    void on_bootstrap_update(block_update_t&& bu);

    void on_swarm_update(block_update_t&& bu);

    void bootstrap_data();

    void bootstrap_peers(
        const std::vector<sn_record_t>& peers) const; // mutex not needed

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const; // mutex not needed

    /// Reliably push message/batch to a service node
    void
    relay_data_reliable(const std::string& blob,
                        const sn_record_t& address) const; // mutex not needed

    void relay_messages(
        const std::vector<storage::Item>& items,
        const std::vector<sn_record_t>& snodes) const; // mutex not needed

    // Conducts any ping peer tests that are due; (this is designed to be called frequently and does
    // nothing if there are no tests currently due).
    void ping_peers();

    /// Pings oxend (as required for uptime proofs)
    void oxend_ping();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record_t& testee, uint64_t test_height,
                               const storage::Item& item);

    void process_storage_test_response(const sn_record_t& testee,
                                       const storage::Item& item,
                                       uint64_t test_height,
                                       std::string status,
                                       std::string answer);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Initiate node ping tests
    void test_reachability(const sn_record_t& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for retesting.
    void report_reachability(const sn_record_t& sn, bool reachable, int previous_failures);

    /// Deprecated; can be removed after HF19
    /// Returns headers to add to the request containing signature info for the given body
    std::vector<std::pair<std::string, std::string>> sign_request(std::string_view body) const;

  public:
    ServiceNode(sn_record_t address,
                const legacy_seckey& skey,
                OxenmqServer& omq_server,
                const std::filesystem::path& db_location,
                bool force_start);

    // Return info about this node as it is advertised to other nodes
    const sn_record_t& own_address() { return our_address_; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(ReachType type);

    // These two are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();

    /// Sends an onion request to the next SS
    void send_onion_to_sn(
            const sn_record_t& sn,
            std::string_view payload,
            OnionRequestMetadata&& data,
            std::function<void(bool success, std::vector<std::string> data)> cb) const;

    bool hf_at_least(int hardfork) const { return hardfork_ >= hardfork; }

    // Return true if the service node is ready to handle requests, which means the storage server
    // is fully initialized (and not trying to shut down), the service node is active and assigned
    // to a swarm and is not syncing.
    //
    // Teturns false and (if `reason` is non-nullptr) sets a reason string during initialization and
    // while shutting down.
    //
    // If this ServiceNode was created with force_start enabled then this function always returns
    // true (except when shutting down); the reason string is still set (when non-null) when errors
    // would have occured without force_start.
    bool snode_ready(std::string* reason = nullptr);

    // Puts the storage server into shutdown mode; this operation is irreversible and should only be
    // used during storage server shutdown.
    void shutdown();

    // Returns true if the storage server is currently shutting down.
    bool shutting_down() const { return shutting_down_; }

    /// Process message received from a client, return false if not in a swarm
    bool process_store(message_t msg);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    // Attempt to find an answer (message body) to the storage test
    std::pair<MessageTestStatus, std::string> process_storage_test_req(uint64_t blk_height,
                                               const legacy_pubkey& tester_addr,
                                               const std::string& msg_hash_hex);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    std::vector<sn_record_t> get_snodes_by_pk(const user_pubkey_t& pk);

    std::vector<sn_record_t> get_swarm_peers();

    /// return all messages for a particular PK (in JSON)
    bool get_all_messages(std::vector<storage::Item>& all_entries) const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<storage::Item>& items);

    /// Deletes all messages belonging to a pubkey; returns the deleted hashes
    std::optional<std::vector<std::string>> delete_all_messages(
            const user_pubkey_t& pubkey);

    /// Delete messages owned by the given pubkey having the given hashes.  Returns the hashes of
    /// any delete messages on success (including the case where no messages are deleted), nullopt
    /// on query failure.
    std::optional<std::vector<std::string>> delete_messages(
            const user_pubkey_t& pubkey,
            const std::vector<std::string_view>& msg_hashes);

    /// Deletes all messages owned by the given pubkey with a timestamp <= `timestamp`.  Returns the
    /// hashes of any deleted messages (including the case where no messages are deleted), nullopt
    /// on query failure.
    std::optional<std::vector<std::string>> delete_messages_before(
            const user_pubkey_t& pubkey, std::chrono::system_clock::time_point timestamp);

    /// Shortens the expiry time of the given messages owned by the given pubkey.  Expiries can only
    /// be shortened (i.e. brought closer to now), not extended into the future.  Returns a vector
    /// of [msgid, newexpiry] pairs indicating the new expiry of any messages found (note that the
    /// new expiry may not have been updated if it was already shorter than the requested time).
    std::optional<std::vector<std::pair<std::string, std::chrono::system_clock::time_point>>>
    update_messages_expiry(
            const user_pubkey_t& pubkey,
            const std::vector<std::string_view>& msg_hashes,
            std::chrono::system_clock::time_point new_exp);

    /// Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    /// shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    /// [msg, newexpiry] for all messages, whether the expiry is updated or not.
    std::optional<std::vector<std::pair<std::string, std::chrono::system_clock::time_point>>>
    update_all_expiries(
            const user_pubkey_t& pubkey,
            std::chrono::system_clock::time_point new_exp);

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    template <typename PubKey>
    std::optional<sn_record_t>
    find_node(const PubKey& pk) const {
        std::lock_guard guard{sn_mutex_};
        if (swarm_)
            return swarm_->find_node(pk);
        return std::nullopt;
    }

    // Called once we have established the initial connection to our local oxend to set up initial
    // data and timers that rely on an oxend connection.
    void on_oxend_connected();

    // Called when oxend notifies us of a new block to update swarm info
    void update_swarms();

    OxenmqServer& omq_server() { return omq_server_; }
};

} // namespace oxen
