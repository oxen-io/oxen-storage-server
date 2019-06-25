#pragma once

#include <Database.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/log/trivial.hpp>
#include <boost/optional.hpp>
#include <boost/thread/thread.hpp>

#include "../common/src/common.h"
#include "lokid_key.h"
#include "pow.hpp"
#include "stats.h"
#include "swarm.h"

static constexpr size_t BLOCK_HASH_CACHE_SIZE = 10;
static constexpr char POW_DIFFICULTY_URL[] = "sentinel.messenger.loki.network";

class Database;

namespace service_node {
namespace storage {
struct Item;
} // namespace storage
} // namespace service_node

namespace http = boost::beast::http;
using request_t = http::request<http::string_body>;

namespace loki {

struct sn_response_t;
struct blockchain_test_answer_t;
struct bc_test_params_t;

class LokidClient;

namespace http_server {
class connection_t;
}

struct lokid_key_pair_t;

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct signature;

using pow_dns_callback_t =
    std::function<void(const std::vector<pow_difficulty_t>&)>;

std::vector<pow_difficulty_t> query_pow_difficulty(std::error_code& ec);

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
    boost::optional<std::function<void()>> give_up_callback_;

    void retry(std::shared_ptr<FailedRequestHandler>&& self);

  public:
    FailedRequestHandler(
        boost::asio::io_context& ioc, const sn_record_t& sn,
        std::shared_ptr<request_t> req,
        boost::optional<std::function<void()>>&& give_up_cb = boost::none);

    ~FailedRequestHandler();
    /// Initiates the timer for retrying (which cannot be done directly in
    /// the constructor as it is not possible to create a shared ptr
    /// to itself before the construction is done)
    void init_timer();
};

enum class MessageTestStatus { SUCCESS, RETRY, ERROR };

/// All service node logic that is not network-specific
class ServiceNode {
    using pub_key_t = std::string;
    using listeners_t = std::vector<connection_ptr>;

    boost::asio::io_context& ioc_;
    boost::asio::io_context& worker_ioc_;
    boost::thread worker_thread_;

    pow_difficulty_t curr_pow_difficulty_{std::chrono::milliseconds(0), 100};
    std::vector<pow_difficulty_t> pow_history_{curr_pow_difficulty_};

    uint64_t block_height_ = 0;
    const LokidClient& lokid_client_;
    std::string block_hash_;
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    sn_record_t our_address_;

    /// Cache for block_height/block_hash mapping
    boost::circular_buffer<std::pair<uint64_t, std::string>>
        block_hashes_cache_{BLOCK_HASH_CACHE_SIZE};

    boost::asio::steady_timer pow_update_timer_;

    boost::asio::steady_timer swarm_update_timer_;

    boost::asio::steady_timer lokid_ping_timer_;

    boost::asio::steady_timer stats_cleanup_timer_;

    /// map pubkeys to a list of connections to be notified
    std::unordered_map<pub_key_t, listeners_t> pk_to_listeners;

    loki::lokid_key_pair_t lokid_key_pair_;

    void push_message(const message_t& msg);

    void save_if_new(const message_t& msg);

    // Save items to the database, notifying listeners as necessary
    void save_bulk(const std::vector<service_node::storage::Item>& items);

    /// request swarm info from the blockchain
    void update_swarms();

    void on_swarm_update(const block_update_t& bu);

    void bootstrap_peers(const std::vector<sn_record_t>& peers) const;

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;

    void attach_signature(std::shared_ptr<request_t>& request,
                          const signature& sig) const;

    void attach_pubkey(std::shared_ptr<request_t>& request) const;

    /// used on push and on swarm bootstrapping
    void send_sn_request(const std::shared_ptr<request_t>& req,
                         const sn_record_t& address) const;
    void
    relay_messages(const std::vector<service_node::storage::Item>& messages,
                   const std::vector<sn_record_t>& snodes) const;

    /// Request swarm structure from the deamon and reset the timer
    void swarm_timer_tick();

    void cleanup_timer_tick();

    /// Update PoW difficulty from DNS text record
    void pow_difficulty_timer_tick(const pow_dns_callback_t cb);

    /// Ping the storage server periodically as required for uptime proofs
    void lokid_ping_timer_tick();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_storage_test_req(const sn_record_t& testee,
                               const service_node::storage::Item& item);

    void send_blockchain_test_req(const sn_record_t& testee,
                                  bc_test_params_t params,
                                  blockchain_test_answer_t answer);

    /// From a peer
    void process_blockchain_test_response(sn_response_t&& res,
                                          blockchain_test_answer_t our_answer,
                                          sn_record_t testee,
                                          uint64_t bc_height);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Select a random message from our database, return false on error
    bool select_random_message(service_node::storage::Item& item);

  public:
    ServiceNode(boost::asio::io_context& ioc,
                boost::asio::io_context& worker_ioc, uint16_t port,
                const loki::lokid_key_pair_t& key_pair,
                const std::string& db_location, LokidClient& lokid_client);

    ~ServiceNode();

    mutable all_stats_t all_stats_;

    // Register a connection as waiting for new data for pk
    void register_listener(const std::string& pk,
                           const connection_ptr& connection);

    // Notify listeners of a new message for pk
    void notify_listeners(const std::string& pk, const message_t& msg);

    // Send "empty" responses to all listeners effectively resetting their
    // connections
    void reset_listeners();

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_t& msg);

    /// Process message relayed from another SN from our swarm
    void process_push(const message_t& msg);

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

    bool is_pubkey_for_us(const std::string& pk) const;

    std::vector<sn_record_t> get_snodes_by_pk(const std::string& pk);

    bool is_snode_address_known(const std::string&);

    /// return all messages for a particular PK (in JSON)
    bool get_all_messages(
        std::vector<service_node::storage::Item>& all_entries) const;

    // Return the current PoW difficulty
    int get_curr_pow_difficulty() const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<service_node::storage::Item>& items);

    void
    set_difficulty_history(const std::vector<pow_difficulty_t>& new_history) {
        pow_history_ = new_history;
        for (const auto& difficulty : pow_history_) {
            if (curr_pow_difficulty_.timestamp < difficulty.timestamp) {
                curr_pow_difficulty_ = difficulty;
            }
        }
        LOKI_LOG(info, "Read PoW difficulty: {}",
                 curr_pow_difficulty_.difficulty);
    }

    std::string get_stats() const { return all_stats_.to_json(true); }
};

} // namespace loki
