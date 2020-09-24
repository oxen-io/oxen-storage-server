#pragma once

#include <Database.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/thread/thread.hpp>

#include "loki_common.h"
#include "lokid_key.h"
#include "notifier.h"
#include "pow.hpp"
#include "reachability_testing.h"
#include "stats.h"
#include "swarm.h"

static constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;
static constexpr int STORAGE_SERVER_HARDFORK = 12;
static constexpr int ENFORCED_REACHABILITY_HARDFORK = 13;
static constexpr int LOKIMQ_ONION_HARDFORK = 15;

class Database;

namespace http = boost::beast::http;
using request_t = http::request<http::string_body>;

namespace lokimq {
struct ConnectionID;
}

namespace loki {

namespace storage {
struct Item;
} // namespace storage

struct sn_response_t;
struct blockchain_test_answer_t;
struct bc_test_params_t;

class LokidClient;
class LokimqServer;

namespace ss_client {
class Request;
enum class ReqMethod;
using Callback = std::function<void(bool success, std::vector<std::string>)>;

} // namespace ss_client

namespace http_server {
class connection_t;
}

struct lokid_key_pair_t;

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct signature;

using pow_dns_callback_t =
    std::function<void(const std::vector<pow_difficulty_t>&)>;

/// Represents failed attempt at communicating with a SNode
/// (currently only for single messages)
class FailedRequestHandler
    : public std::enable_shared_from_this<FailedRequestHandler> {
    boost::asio::io_context& ioc_;
    boost::asio::steady_timer retry_timer_;
    sn_record_t sn_;
    const std::shared_ptr<request_t> request_;

    uint32_t attempt_count_ = 0;

    /// Call this if we give up re-transmitting
    std::function<void()> give_up_callback_;

    void retry(std::shared_ptr<FailedRequestHandler>&& self);

  public:
    FailedRequestHandler(boost::asio::io_context& ioc, const sn_record_t& sn,
                         std::shared_ptr<request_t> req,
                         std::function<void()> give_up_cb = nullptr);

    ~FailedRequestHandler();
    /// Initiates the timer for retrying (which cannot be done directly in
    /// the constructor as it is not possible to create a shared ptr
    /// to itself before the construction is done)
    void init_timer();
};

/// WRONG_REQ - request was ignored as not valid (e.g. incorrect tester)
enum class MessageTestStatus { SUCCESS, RETRY, ERROR, WRONG_REQ };

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

/// All service node logic that is not network-specific
class ServiceNode {
    using pub_key_t = std::string;
    using listeners_t = std::vector<connection_ptr>;

    boost::asio::io_context& ioc_;
    boost::asio::io_context& worker_ioc_;
    boost::thread worker_thread_;

    // We set the default difficulty to some low value, so that we don't reject
    // clients unnecessarily before we get the DNS record
    pow_difficulty_t curr_pow_difficulty_{std::chrono::milliseconds(0), 1};
    std::vector<pow_difficulty_t> pow_history_{curr_pow_difficulty_};

    bool force_start_ = false;
    bool syncing_ = true;
    int hardfork_ = 0;
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    const LokidClient& lokid_client_;
    std::string block_hash_;
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    sn_record_t our_address_;

    /// Cache for block_height/block_hash mapping
    boost::circular_buffer<std::pair<uint64_t, std::string>>
        block_hashes_cache_{BLOCK_HASH_CACHE_SIZE};

    boost::asio::steady_timer pow_update_timer_;

    boost::asio::steady_timer check_version_timer_;

    boost::asio::steady_timer swarm_update_timer_;

    boost::asio::steady_timer lokid_ping_timer_;

    boost::asio::steady_timer stats_cleanup_timer_;

    boost::asio::steady_timer peer_ping_timer_;

    /// Used to periodially send messages from relay_buffer_
    boost::asio::steady_timer relay_timer_;

    loki::lokid_key_pair_t lokid_key_pair_;

    // Need to make sure we only use this to get lmq() object and
    // not call any method that would in turn call a method in SN
    // causing a deadlock
    LokimqServer& lmq_server_;

    reachability_records_t reach_records_;

    /// Container for recently received messages directly from
    /// clients;
    std::vector<message_t> relay_buffer_;

    Notifier notifier_;

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

    /// Request swarm structure from the deamon and reset the timer
    void swarm_timer_tick();

    void cleanup_timer_tick();

    void ping_peers_tick();

    void relay_buffered_messages();

    /// Check the latest version from DNS text record
    void check_version_timer_tick(); // mutex not needed
    /// Update PoW difficulty from DNS text record
    void
    pow_difficulty_timer_tick(const pow_dns_callback_t cb); // mutex not needed

    /// Ping the storage server periodically as required for uptime proofs
    void lokid_ping_timer_tick();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record_t& testee, uint64_t test_height,
                               const storage::Item& item);

    void send_blockchain_test_req(const sn_record_t& testee,
                                  bc_test_params_t params, uint64_t test_height,
                                  blockchain_test_answer_t answer);

    /// Report `sn` to Lokid as unreachable
    void report_node_reachability(const sn_pub_key_t& sn, bool reachable);

    void process_storage_test_response(const sn_record_t& testee,
                                       const storage::Item& item,
                                       uint64_t test_height,
                                       sn_response_t&& res);

    void process_reach_test_result(const sn_pub_key_t& pk, ReachType type,
                                   bool success);

    /// From a peer
    void process_blockchain_test_response(sn_response_t&& res,
                                          blockchain_test_answer_t our_answer,
                                          sn_record_t testee,
                                          uint64_t bc_height);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Select a random message from our database, return false on error
    bool select_random_message(storage::Item& item); // mutex not needed

    // Ping some node and record its reachability
    void test_reachability(const sn_record_t& sn); // mutex not needed

    void sign_request(std::shared_ptr<request_t>& req) const;

  public:
    ServiceNode(boost::asio::io_context& ioc,
                boost::asio::io_context& worker_ioc, uint16_t port,
                LokimqServer& lmq_server,
                const loki::lokid_key_pair_t& key_pair,
                const std::string& ed25519hex, const std::string& db_location,
                LokidClient& lokid_client, const bool force_start);

    ~ServiceNode();

    // Return info about this node as it is advertised to other nodes
    const sn_record_t& own_address() { return our_address_; }

    // Record the time of our last being tested over lmq/http
    void update_last_ping(ReachType type);

    // These two are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();

    // Add `pubkey` to the list of pubkeys to notify
    void add_notify_pubkey(const lokimq::ConnectionID& cid,
                           std::string_view pubkey);

    size_t get_notify_subscriber_count() const;

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
    // Send by either http or lmq
    void send_to_sn(const sn_record_t& sn, ss_client::ReqMethod method,
                    ss_client::Request req, ss_client::Callback cb) const;

    // Return true if the service node is ready to start running
    bool snode_ready(std::string* reason = nullptr);

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_t& msg);

    /// Process incoming blob of messages: add to DB if new
    void process_push_batch(const std::string& blob);

    /// request blockchain test from a peer
    void perform_blockchain_test(
        bc_test_params_t params,
        std::function<void(blockchain_test_answer_t)>&& cb) const;

    // Attempt to find an answer (message body) to the storage test
    MessageTestStatus process_storage_test_req(uint64_t blk_height,
                                               const std::string& tester_addr,
                                               const std::string& msg_hash,
                                               std::string& answer);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    std::vector<sn_record_t> get_snodes_by_pk(const user_pubkey_t& pk);

    bool is_snode_address_known(const std::string&);

    /// return all messages for a particular PK (in JSON)
    bool get_all_messages(std::vector<storage::Item>& all_entries) const;

    // Return the current PoW difficulty
    int get_curr_pow_difficulty() const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<storage::Item>& items);

    void
    set_difficulty_history(const std::vector<pow_difficulty_t>& new_history);

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    std::optional<sn_record_t>
    find_node_by_x25519_bin(const sn_pub_key_t& address) const;

    std::optional<sn_record_t>
    find_node_by_ed25519_pk(const std::string& pk) const;
};

} // namespace loki
