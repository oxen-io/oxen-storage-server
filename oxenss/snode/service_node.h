#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <oxenss/crypto/keys.h>
#include <oxenss/common/message.h>
#include <oxenss/storage/database.hpp>
#include "network.h"
#include "swarm.h"
#include "reachability_testing.h"
#include "stats.h"
#include "contacts.h"

namespace oxenss::server {
class OMQ;
class QUIC;
class MQBase;
}  // namespace oxenss::server

namespace oxenss::rpc {
struct OnionRequestMetadata;
}

namespace oxenss::http {
class Client;
}

namespace oxenss::snode {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;

// How long we wait for a HTTPS or OMQ ping response from another SN when ping testing
inline constexpr auto SN_PING_TIMEOUT = 5s;

// Timeout for bootstrap node OMQ requests
inline constexpr auto BOOTSTRAP_TIMEOUT = 10s;

/// We test based on the height a few blocks back to minimise discrepancies between nodes (we
/// could also use checkpoints, but that is still not bulletproof: swarms are calculated based
/// on the latest block, so they might be still different and thus derive different pairs)
inline constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

// We use the network hardfork and snode revision from oxend to version-gate upgrade features.
using hf_revision = std::pair<int, int>;

// The earliest hardfork *this* version of storage server will work on:
inline constexpr hf_revision STORAGE_SERVER_HARDFORK = {19, 6};

// The storage server version at which initial handshaking is supported before attempting a swarm
// message transfer.
inline constexpr std::array<uint16_t, 3> NEW_SWARM_MEMBER_HANDSHAKE_VERSION = {2, 10, 0};

class Swarm;

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

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
    std::atomic<bool> got_first_response_ = false;
    bool force_start_ = false;
    std::atomic<bool> shutting_down_ = false;
    hf_revision hardfork_ = {0, 0};
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    std::string block_hash_;
    std::unique_ptr<Database> db_;
    std::weak_ptr<http::Client> http_;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const crypto::legacy_keypair our_keys_;
    const contact our_contact_;

    Network network_;
    Swarm swarm_{network_, our_keys_.pub};

    server::OMQ& omq_server_;
    std::vector<server::MQBase*> mq_servers_;

    std::atomic<int> oxend_pings_ =
            0;  // Consecutive successful pings, used for batching logs about it

    // Will be set to true while we have an outstanding update_swarms() call so that we squelch
    // other update_swarms() until it finishes (or fails), to avoid spamming oxend (particularly
    // when syncing when we get tons of block notifications quickly).
    std::atomic<bool> updating_swarms_ = false;

    reachability_testing reach_records_;

    mutable all_stats all_stats_;

    mutable std::recursive_mutex sn_mutex_;

    void send_notifies(message m);

    // Save multiple messages to the database at once (i.e. in a single transaction)
    void save_bulk(const std::vector<message>& msgs);

    void process_snodes_update(std::string_view data);

    void on_bootstrap_update(block_update&& bu);

    void on_snodes_update(block_update&& bu);

    // Called periodically to attempt to initiate transfers to new snode members
    void check_new_members();

    // Called if our oxend looks like it is missing lots of records when we first get data from it
    // to load initial data (especially contact info) from the bootstrap nodes.
    void bootstrap_fallback();

    void bootstrap_swarms(const std::set<swarm_id_t>& swarms = {}) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;  // mutex not needed

    /// Reliably push message/batch to a service node.  The node must be contactable!
    void relay_data_reliable(
            const std::string& blob,
            const crypto::legacy_pubkey& snpk,
            const contact& ct) const;  // mutex not needed

    void relay_messages(
            const std::vector<message>& msgs,
            const std::set<crypto::legacy_pubkey>& snodes) const;  // mutex not needed

    // Conducts any ping peer tests that are due; (this is designed to be called frequently and
    // does nothing if there are no tests currently due).
    void ping_peers();

    /// Pings oxend (as required for uptime proofs)
    void oxend_ping();

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Initiate node ping tests
    void test_reachability(const crypto::legacy_pubkey& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for
    // retesting.
    void report_reachability(
            const crypto::legacy_pubkey& sn, bool reachable, int previous_failures);

  public:
    ServiceNode(
            const crypto::legacy_keypair& keys,
            const contact& contact,
            server::OMQ& omq_server,
            const std::filesystem::path& db_location,
            bool force_start);

    Database& get_db() { return *db_; }
    const Database& get_db() const { return *db_; }

    const Network& network() { return network_; }

    const Swarm& swarm() { return swarm_; }

    Contacts& contacts() { return network_.contacts; }
    const Contacts& contacts() const { return network_.contacts; }

    const contact& own_address() { return our_contact_; }

    // Adds a MQ server, i.e. QUIC.  The OMQ server is added automatically during construction and
    // should not be added.
    void register_mq_server(server::MQBase* server);

    // Sets the http client needed to perform HTTPS reachability tests
    void set_http_client(std::weak_ptr<http::Client> client) { http_ = std::move(client); }

    // Return info about this node as it is advertised to other nodes
    const crypto::legacy_pubkey& own_pubkey() const { return our_keys_.pub; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(ReachType type);

    // These three are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();
    void record_retrieve_request();

    /// Sends an onion request to the next SS
    void send_onion_to_sn(
            const contact& ct,
            std::string_view payload,
            rpc::OnionRequestMetadata&& data,
            std::function<void(bool success, std::vector<std::string> data)> cb) const;

    // Returns true if the given x pubkey is recognized as one of our current swarm members
    bool is_swarm_peer(const crypto::x25519_pubkey& xpk);

    const hf_revision& hf() const { return hardfork_; }

    const uint64_t& blockheight() const { return block_height_; }

    bool hf_at_least(hf_revision version) const { return hardfork_ >= version; }

    // Return true if the service node is ready to handle requests, which means the storage
    // server is fully initialized (and not trying to shut down), the service node is active and
    // assigned to a swarm and is not syncing.
    //
    // Returns false and, if `reason` is non-nullptr, sets a reason string during initialization and
    // while shutting down.
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

    /// Process message received from a client, return false if not in a swarm.  If new_msg is not
    /// nullptr, sets it to true if we stored as a new message, false if we already had it.  If
    /// `expiry` is non-null it will be set to the message's expiry: for a new message this is the
    /// given expiry; for existing messages this is the message's new expiry (which might have been
    /// extended to match the one in `msg`, if later).
    bool process_store(
            message msg,
            bool* new_msg = nullptr,
            std::chrono::system_clock::time_point* expiry = nullptr);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(std::string_view blob, std::string_view sender);

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    // Called once we have established the initial connection to our local oxend to set up
    // initial data and timers that rely on an oxend connection.  This blocks until we get an
    // initial service node block update back from oxend.
    void on_oxend_connected();

    // Parses the result of a `get_service_nodes` oxend rpc request, loading the service node state
    // into our contact details and returning a "block_update" struct containing various details of
    // the update.  Returns a nullopt if the RPC response indicates that nothing has changed.
    std::optional<block_update> update_snodes(std::string_view response_body);

    // Called when oxend notifies us of a new block to update swarm info
    void update_swarms(std::promise<bool>* on_completion = nullptr);

    server::OMQ& omq_server() { return omq_server_; }
};

}  // namespace oxenss::snode

template <>
inline constexpr bool oxenss::to_string_formattable<oxenss::snode::SnodeStatus> = true;
