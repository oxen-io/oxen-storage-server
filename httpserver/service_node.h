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

/// We test based on the height a few blocks back to minimise discrepancies between nodes (we could
/// also use checkpoints, but that is still not bulletproof: swarms are calculated based on the
/// latest block, so they might be still different and thus derive different pairs)
inline constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

// We use the network hardfork and snode revision from oxend to version-gate upgrade features.
using hf_revision = std::pair<int, int>;

// The earliest hardfork *this* version of storage server will work on:
inline constexpr hf_revision STORAGE_SERVER_HARDFORK = {18, 0};
// HF at which we switch to /ping_test/v1 instead of /swarms/ping_test/v1 for HTTPS pings
inline constexpr hf_revision HARDFORK_HTTPS_PING_TEST_URL = {18, 1};
// HF at which we switch to OMQ storage tests instead of HTTPS
inline constexpr hf_revision HARDFORK_OMQ_STORAGE_TESTS = {18, 1};
// HF at which `store` requests become recursive (rather than having unreported background
// distribution).
inline constexpr hf_revision HARDFORK_RECURSIVE_STORE = {18, 1};
// When we start using the more compact BT message serialization
inline constexpr hf_revision HARDFORK_BT_MESSAGE_SERIALIZATION = {18, 1};
// Hardfork where we switch the hash function to base64(blake2b) from hex(sha512)
inline constexpr hf_revision HARDFORK_HASH_BLAKE2B = {18, 1};

class OxenmqServer;
struct OnionRequestMetadata;
class Swarm;

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

/// All service node logic that is not network-specific
class ServiceNode {
    bool syncing_ = true;
    bool active_ = false;
    bool got_first_response_ = false;
    std::condition_variable first_response_cv_;
    std::mutex first_response_mutex_;
    bool force_start_ = false;
    std::atomic<bool> shutting_down_ = false;
    hf_revision hardfork_ = {0, 0};
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    std::string block_hash_;
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const sn_record our_address_;
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

    // Save multiple messages to the database at once (i.e. in a single transaction)
    void save_bulk(const std::vector<message>& msgs);

    void on_bootstrap_update(block_update&& bu);

    void on_swarm_update(block_update&& bu);

    void bootstrap_data();

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms = {}) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const; // mutex not needed

    /// Reliably push message/batch to a service node
    void
    relay_data_reliable(const std::string& blob,
                        const sn_record& address) const; // mutex not needed

    void relay_messages(
        const std::vector<message>& msgs,
        const std::vector<sn_record>& snodes) const; // mutex not needed

    // Conducts any ping peer tests that are due; (this is designed to be called frequently and does
    // nothing if there are no tests currently due).
    void ping_peers();

    /// Pings oxend (as required for uptime proofs)
    void oxend_ping();

    /// Return tester/testee pair based on block_height
    std::optional<std::pair<sn_record, sn_record>> derive_tester_testee(uint64_t block_height);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record& testee, uint64_t test_height,
                               const message& msg);

    void process_storage_test_response(const sn_record& testee,
                                       const message& msg,
                                       uint64_t test_height,
                                       std::string status,
                                       std::string answer);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Initiate node ping tests
    void test_reachability(const sn_record& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for retesting.
    void report_reachability(const sn_record& sn, bool reachable, int previous_failures);

    /// Deprecated; can be removed after HF19
    /// Returns headers to add to the request containing signature info for the given body
    std::vector<std::pair<std::string, std::string>> sign_request(std::string_view body) const;

  public:
    ServiceNode(sn_record address,
                const legacy_seckey& skey,
                OxenmqServer& omq_server,
                const std::filesystem::path& db_location,
                bool force_start);

    // Return info about this node as it is advertised to other nodes
    const sn_record& own_address() { return our_address_; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(ReachType type);

    // These two are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();

    /// Sends an onion request to the next SS
    void send_onion_to_sn(
            const sn_record& sn,
            std::string_view payload,
            OnionRequestMetadata&& data,
            std::function<void(bool success, std::vector<std::string> data)> cb) const;

    bool hf_at_least(hf_revision version) const { return hardfork_ >= version; }

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

    /// Process message received from a client, return false if not in a swarm.  If new_msg is not
    /// nullptr, sets it to true if we stored as a new message, false if we already had it.
    bool process_store(message msg, bool* new_msg = nullptr);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    // Attempt to find an answer (message body) to the storage test
    std::pair<MessageTestStatus, std::string> process_storage_test_req(uint64_t blk_height,
                                               const legacy_pubkey& tester_addr,
                                               const std::string& msg_hash_hex);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    SwarmInfo get_swarm(const user_pubkey_t& pk);

    std::vector<sn_record> get_swarm_peers();

    std::vector<message> get_all_messages() const;

    /// return all messages for a particular PK
    std::vector<message> retrieve(const user_pubkey_t& pubkey, const std::string& last_hash);

    /// Deletes all messages belonging to a pubkey; returns the deleted hashes
    std::optional<std::vector<std::string>> delete_all_messages(
            const user_pubkey_t& pubkey);

    /// Delete messages owned by the given pubkey having the given hashes.  Returns the hashes of
    /// any delete messages on success (including the case where no messages are deleted), nullopt
    /// on query failure.
    std::optional<std::vector<std::string>> delete_messages(
            const user_pubkey_t& pubkey,
            const std::vector<std::string>& msg_hashes);

    /// Deletes all messages owned by the given pubkey with a timestamp <= `timestamp`.  Returns the
    /// hashes of any deleted messages (including the case where no messages are deleted), nullopt
    /// on query failure.
    std::optional<std::vector<std::string>> delete_messages_before(
            const user_pubkey_t& pubkey, std::chrono::system_clock::time_point timestamp);

    /// Shortens the expiry time of the given messages owned by the given pubkey.  Expiries can only
    /// be shortened (i.e. brought closer to now), not extended into the future.  Returns a vector
    /// of [msgid, newexpiry] pairs indicating the new expiry of any messages found (note that the
    /// new expiry may not have been updated if it was already shorter than the requested time).
    std::optional<std::vector<std::string>>
    update_messages_expiry(
            const user_pubkey_t& pubkey,
            const std::vector<std::string>& msg_hashes,
            std::chrono::system_clock::time_point new_exp);

    /// Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    /// shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    /// [msg, newexpiry] for all messages, whether the expiry is updated or not.
    std::optional<std::vector<std::string>>
    update_all_expiries(
            const user_pubkey_t& pubkey,
            std::chrono::system_clock::time_point new_exp);

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    template <typename PubKey>
    std::optional<sn_record>
    find_node(const PubKey& pk) const {
        std::lock_guard guard{sn_mutex_};
        if (swarm_)
            return swarm_->find_node(pk);
        return std::nullopt;
    }

    // Called once we have established the initial connection to our local oxend to set up initial
    // data and timers that rely on an oxend connection.  This blocks until we get an initial
    // service node block update back from oxend.
    void on_oxend_connected();

    // Called when oxend notifies us of a new block to update swarm info
    void update_swarms();

    OxenmqServer& omq_server() { return omq_server_; }
};

} // namespace oxen
