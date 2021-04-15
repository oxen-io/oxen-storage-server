#pragma once

#include <Database.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/circular_buffer.hpp>

#include "oxen_common.h"
#include "oxend_key.h"
#include "reachability_testing.h"
#include "stats.h"
#include "swarm.h"

namespace http = boost::beast::http;
using request_t = http::request<http::string_body>;

namespace oxen {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;
inline constexpr int STORAGE_SERVER_HARDFORK = 12;
inline constexpr int ENFORCED_REACHABILITY_HARDFORK = 13;
inline constexpr int OXENMQ_ONION_HARDFORK = 15;

namespace storage {
struct Item;
} // namespace storage

struct sn_response_t;

class OxenmqServer;

namespace ss_client {
class Request;
enum class ReqMethod;
using Callback = std::function<void(bool success, std::vector<std::string>)>;

} // namespace ss_client

namespace http_server {
class connection_t;
}

struct oxend_key_pair_t;

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct signature;

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

/// All service node logic that is not network-specific
class ServiceNode {
    using listeners_t = std::vector<connection_ptr>;

    boost::asio::io_context& ioc_;

    bool syncing_ = true;
    bool active_ = true;
    bool got_first_response_ = false;
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
    boost::circular_buffer<std::pair<uint64_t, std::string>>
        block_hashes_cache_{BLOCK_HASH_CACHE_SIZE};

    boost::asio::steady_timer oxend_ping_timer_;

    boost::asio::steady_timer stats_cleanup_timer_;

    boost::asio::steady_timer peer_ping_timer_;

    /// Used to periodially send messages from relay_buffer_
    boost::asio::steady_timer relay_timer_;

    // Need to make sure we only use this to get OxenMQ object and
    // not call any method that would in turn call a method in SN
    // causing a deadlock
    OxenmqServer& lmq_server_;

    bool force_start_ = false;

    reachability_testing reach_records_;

    /// Container for recently received messages directly from
    /// clients;
    std::vector<message_t> relay_buffer_;

    mutable all_stats_t all_stats_;

    mutable std::recursive_mutex sn_mutex_;

    void save_if_new(const message_t& msg);

    // Save items to the database, notifying listeners as necessary
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

    void attach_signature(std::shared_ptr<request_t>& request,
                          const signature& sig) const; // mutex not needed

    /// Reliably push message/batch to a service node
    void
    relay_data_reliable(const std::string& blob,
                        const sn_record_t& address) const; // mutex not needed

    template <typename Message>
    void relay_messages(
        const std::vector<Message>& messages,
        const std::vector<sn_record_t>& snodes) const; // mutex not needed

    void cleanup_timer_tick();

    void ping_peers_tick();

    void relay_buffered_messages();

    /// Ping oxend periodically as required for uptime proofs
    void oxend_ping_timer_tick();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record_t& testee, uint64_t test_height,
                               const storage::Item& item);

    void process_storage_test_response(const sn_record_t& testee,
                                       const storage::Item& item,
                                       uint64_t test_height,
                                       sn_response_t&& res);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Select a random message from our database, return false on error
    bool select_random_message(storage::Item& item); // mutex not needed

    // Initiate node ping tests
    void test_reachability(const sn_record_t& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for retesting.
    void report_reachability(const sn_record_t& sn, bool reachable, int previous_failures);

    void sign_request(std::shared_ptr<request_t>& req) const;

  public:
    ServiceNode(boost::asio::io_context& ioc,
                sn_record_t address,
                const legacy_seckey& skey,
                OxenmqServer& omq_server,
                const std::string& db_location,
                bool force_start);

    // Return info about this node as it is advertised to other nodes
    const sn_record_t& own_address() { return our_address_; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(bool omq);

    // These two are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();

    // This is new, so it does not need to support http, thus new (if temp)
    // method
    void send_onion_to_sn_v1(const sn_record_t& sn, const std::string& payload,
                             const std::string& eph_key,
                             ss_client::Callback cb) const;

    /// Same as v1, but using the new protocol (ciphertext as binary)
    void send_onion_to_sn_v2(const sn_record_t& sn, const std::string& payload,
                             const std::string& eph_key,
                             ss_client::Callback cb) const;

    // TODO: move this eventually out of SN
    // Send by either http or omq
    void send_to_sn(const sn_record_t& sn, ss_client::ReqMethod method,
                    ss_client::Request req, ss_client::Callback cb) const;

    // Return true if the service node is ready to start running
    bool snode_ready(std::string* reason = nullptr);

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_t& msg);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    // Attempt to find an answer (message body) to the storage test
    MessageTestStatus process_storage_test_req(uint64_t blk_height,
                                               const legacy_pubkey& tester_addr,
                                               const std::string& msg_hash,
                                               std::string& answer);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    std::vector<sn_record_t> get_snodes_by_pk(const user_pubkey_t& pk);

    /// return all messages for a particular PK (in JSON)
    bool get_all_messages(std::vector<storage::Item>& all_entries) const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<storage::Item>& items);

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

    OxenmqServer& omq_server() { return lmq_server_; }
};

} // namespace oxen
