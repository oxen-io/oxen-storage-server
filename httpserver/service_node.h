#pragma once

#include <Database.hpp>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#include "common.h"
#include "lokid_key.h"
#include "swarm.h"

static constexpr uint16_t SNODE_PORT = 8080;
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

namespace http_server {
class connection_t;
}

struct lokid_key_pair_t;

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct signature;

struct snode_stats_t {

    // how many times a single push failed
    uint64_t relay_fails = 0;
};

int query_pow_difficulty();

/// Represents failed attempt at communicating with a SNode
/// (currently only for single messages)
class FailedRequestHandler
    : public std::enable_shared_from_this<FailedRequestHandler> {
    boost::asio::io_context& ioc_;
    boost::asio::steady_timer retry_timer_;
    sn_record_t sn_;
    const std::shared_ptr<request_t> request_;

    uint32_t attempt_count_ = 0;

    void retry(std::shared_ptr<FailedRequestHandler>&& self);

  public:
    FailedRequestHandler(boost::asio::io_context& ioc, const sn_record_t& sn,
                         std::shared_ptr<request_t> req);

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

    int pow_difficulty_ = 100;
    uint64_t block_height_ = 0;
    const uint16_t lokid_rpc_port_;
    std::string block_hash_ = "";
    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;
    // performance report for other snodes
    mutable std::unordered_map<sn_record_t, snode_stats_t> snode_report_;

    sn_record_t our_address_;

    /// Cache for block_height/block_hash mapping
    boost::circular_buffer<std::pair<uint64_t, std::string>>
        block_hashes_cache_{BLOCK_HASH_CACHE_SIZE};

    boost::asio::steady_timer pow_update_timer_;

    boost::asio::steady_timer swarm_update_timer_;

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

    /// used on push and on swarm bootstrapping
    void send_sn_request(const std::shared_ptr<request_t>& req,
                         const sn_record_t& address) const;
    void
    relay_messages(const std::vector<service_node::storage::Item>& messages,
                   const std::vector<sn_record_t>& snodes) const;

    /// Request swarm structure from the deamon and reset the timer
    void swarm_timer_tick();

    /// Update PoW difficulty from DNS text record
    void pow_difficulty_timer_tick();

    /// Return tester/testee pair based on block_height
    bool derive_tester_testee(uint64_t block_height, sn_record_t& tester,
                              sn_record_t& testee);

    /// Send a request to a SN under test
    void send_message_test_req(const sn_record_t& testee,
                               const service_node::storage::Item& item);

    /// Check if it is our turn to test and initiate peer test if so
    void initiate_peer_test();

    // Select a random message from our database, return false on error
    bool select_random_message(service_node::storage::Item& item);

  public:
    ServiceNode(boost::asio::io_context& ioc, uint16_t port,
                const loki::lokid_key_pair_t& key_pair,
                const std::string& db_location, uint16_t lokid_rpc_port);

    ~ServiceNode();

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

    // Attempt to find an answer (message body) to the message test
    MessageTestStatus process_msg_test_req(uint64_t blk_height,
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
    int get_pow_difficulty() const;

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<service_node::storage::Item>& items);
};

} // namespace loki
