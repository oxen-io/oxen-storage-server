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

#include <cpr/async_wrapper.h>
#include <oxenss/storage/database.hpp>
#include <oxenss/crypto/keys.h>
#include "reachability_testing.h"
#include "stats.h"
#include "swarm.h"

namespace oxenss::quic {
struct Endpoint;
}

namespace oxenss::rpc {
struct OnionRequestMetadata;
}

namespace oxenss::server {
class OMQ;
}

namespace oxenss::snode {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;

// How long we wait for a HTTPS or OMQ ping response from another SN when ping testing
inline constexpr auto SN_PING_TIMEOUT = 5s;

// How long we wait for a storage test response (HTTPS until HF19, then OMQ)
inline constexpr auto STORAGE_TEST_TIMEOUT = 15s;

// Timeout for bootstrap node OMQ requests
inline constexpr auto BOOTSTRAP_TIMEOUT = 10s;

/// We test based on the height a few blocks back to minimise discrepancies between nodes (we
/// could also use checkpoints, but that is still not bulletproof: swarms are calculated based
/// on the latest block, so they might be still different and thus derive different pairs)
inline constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

// We use the network hardfork and snode revision from oxend to version-gate upgrade features.
using hf_revision = std::pair<int, int>;

// The earliest hardfork *this* version of storage server will work on:
inline constexpr hf_revision STORAGE_SERVER_HARDFORK = {19, 3};

class Swarm;

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

constexpr std::string_view to_string(SnodeStatus status) {
    switch (status) {
        case SnodeStatus::UNSTAKED: return "Unstaked"sv;
        case SnodeStatus::DECOMMISSIONED: return "Decommissioned"sv;
        case SnodeStatus::ACTIVE: return "Active"sv;
        case SnodeStatus::UNKNOWN: return "Unknown"sv;
    }
    return "Unknown"sv;
}

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

    // Accessor to the quic endpoint to make requests through
    std::shared_ptr<oxenss::quic::Endpoint> quic;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const sn_record our_address_;
    const crypto::legacy_seckey our_seckey_;

    /// Cache for block_height/block_hash mapping
    std::map<uint64_t, std::string> block_hashes_cache_;

    // Need to make sure we only use this to get OxenMQ object and
    // not call any method that would in turn call a method in SN
    // causing a deadlock
    server::OMQ& omq_server_;

    std::atomic<int> oxend_pings_ =
            0;  // Consecutive successful pings, used for batching logs about it

    // Will be set to true while we have an outstanding update_swarms() call so that we squelch
    // other update_swarms() until it finishes (or fails), to avoid spamming oxend (particularly
    // when syncing when we get tons of block notifications quickly).
    std::atomic<bool> updating_swarms_ = false;

    reachability_testing reach_records_;

    mutable all_stats all_stats_;

    mutable std::recursive_mutex sn_mutex_;

    std::forward_list<cpr::AsyncWrapper<void>> outstanding_https_reqs_;

    void send_notifies(message m);

    // Save multiple messages to the database at once (i.e. in a single transaction)
    void save_bulk(const std::vector<message>& msgs);

    void on_bootstrap_update(block_update&& bu);

    void on_swarm_update(block_update&& bu);

    void bootstrap_data();

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms = {}) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;  // mutex not needed

    /// Reliably push message/batch to a service node
    void relay_data_reliable(
            const std::string& blob,
            const sn_record& address) const;  // mutex not needed

    void relay_messages(
            const std::vector<message>& msgs,
            const std::vector<sn_record>& snodes) const;  // mutex not needed

    // Conducts any ping peer tests that are due; (this is designed to be called frequently and
    // does nothing if there are no tests currently due).
    void ping_peers();

    /// Pings oxend (as required for uptime proofs)
    void oxend_ping();

    /// Return tester/testee pair based on block_height
    std::optional<std::pair<sn_record, sn_record>> derive_tester_testee(uint64_t block_height);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record& testee, uint64_t test_height, const message& msg);

    void process_storage_test_response(
            const sn_record& testee,
            const message& msg,
            uint64_t test_height,
            std::string status,
            std::string answer);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Initiate node ping tests
    void test_reachability(const sn_record& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for
    // retesting.
    void report_reachability(const sn_record& sn, bool reachable, int previous_failures);

  public:
    ServiceNode(
            sn_record address,
            const crypto::legacy_seckey& skey,
            server::OMQ& omq_server,
            const std::filesystem::path& db_location,
            bool force_start);

    Database& get_db() { return *db_; }
    const Database& get_db() const { return *db_; }

    void link_start_quic(const std::shared_ptr<oxenss::quic::Endpoint>&);

    // Return info about this node as it is advertised to other nodes
    const sn_record& own_address() { return our_address_; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(ReachType type);

    // These three are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();
    void record_retrieve_request();

    /// Sends an onion request to the next SS
    void send_onion_to_sn(
            const sn_record& sn,
            std::string_view payload,
            rpc::OnionRequestMetadata&& data,
            std::function<void(bool success, std::vector<std::string> data)> cb) const;

    const hf_revision& hf() const { return hardfork_; }

    const uint64_t& blockheight() const { return block_height_; }

    bool hf_at_least(hf_revision version) const { return hardfork_ >= version; }

    // Return true if the service node is ready to handle requests, which means the storage
    // server is fully initialized (and not trying to shut down), the service node is active and
    // assigned to a swarm and is not syncing.
    //
    // Teturns false and (if `reason` is non-nullptr) sets a reason string during initialization
    // and while shutting down.
    //
    // If this ServiceNode was created with force_start enabled then this function always
    // returns true (except when shutting down); the reason string is still set (when non-null)
    // when errors would have occurred without force_start.
    bool snode_ready(std::string* reason = nullptr);

    // Puts the storage server into shutdown mode; this operation is irreversible and should
    // only be used during storage server shutdown.
    void shutdown();

    // Returns true if the storage server is currently shutting down.
    bool shutting_down() const { return shutting_down_; }

    /// Process message received from a client, return false if not in a swarm.  If new_msg is
    /// not nullptr, sets it to true if we stored as a new message, false if we already had it.
    bool process_store(message msg, bool* new_msg = nullptr);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    // Attempt to find an answer (message body) to the storage test
    std::pair<MessageTestStatus, std::string> process_storage_test_req(
            uint64_t blk_height,
            const crypto::legacy_pubkey& tester_addr,
            const std::string& msg_hash_hex);

    bool is_pubkey_for_us(const user_pubkey& pk) const;

    std::optional<SwarmInfo> get_swarm(const user_pubkey& pk) const;

    std::vector<sn_record> get_swarm_peers() const;

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    template <typename PubKey>
    std::optional<sn_record> find_node(const PubKey& pk) const {
        std::lock_guard guard{sn_mutex_};
        if (swarm_)
            return swarm_->find_node(pk);
        return std::nullopt;
    }

    // Called once we have established the initial connection to our local oxend to set up
    // initial data and timers that rely on an oxend connection.  This blocks until we get an
    // initial service node block update back from oxend.
    void on_oxend_connected();

    // Called when oxend notifies us of a new block to update swarm info
    void update_swarms();

    server::OMQ& omq_server() { return omq_server_; }
};

}  // namespace oxenss::snode

template <>
inline constexpr bool oxenss::to_string_formattable<oxenss::snode::SnodeStatus> = true;
