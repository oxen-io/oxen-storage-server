#pragma once

#include <Database.hpp>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/optional.hpp>

#include "common.h"
#include "swarm.h"

static constexpr uint16_t SNODE_PORT = 8080;

class Database;

namespace service_node {
namespace storage {
struct Item;
} // namespace storage
} // namespace service_node

namespace loki {

namespace http_server {
class connection_t;
}

using connection_ptr = std::shared_ptr<http_server::connection_t>;

class Swarm;

struct snode_stats_t {

    // how many times a single push failed
    uint64_t relay_fails = 0;
};

/// All service node logic that is not network-specific
class ServiceNode {
    using pub_key_t = std::string;
    using listeners_t = std::vector<connection_ptr>;

    boost::asio::io_context& ioc_;

    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;
    // performance report for other snodes
    mutable std::unordered_map<sn_record_t, snode_stats_t> snode_report_;

    sn_record_t our_address_;

    boost::asio::steady_timer update_timer_;

    /// map pubkeys to a list of connections to be notified
    std::unordered_map<pub_key_t, listeners_t> pk_to_listeners;

    void push_message(const message_t& msg);

    void save_if_new(const message_t& msg);

    /// request swarm info from the blockchain
    void update_swarms();

    void on_swarm_update(all_swarms_t all_swarms);

    void bootstrap_peers(const std::vector<sn_record_t>& peers) const;

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;

    /// used on push and on swarm bootstrapping
    void relay_one(const message_t& msg, sn_record_t address) const;

    /// used for SN bootstrapping
    void relay_batch(const std::string& data, sn_record_t address) const;

  public:
    ServiceNode(boost::asio::io_context& ioc, uint16_t port,
                const std::vector<uint8_t>& public_key,
                const std::string& dbLocation);

    ~ServiceNode();

    // Register a connection as waiting for new data for pk
    void register_listener(const std::string& pk,
                           const connection_ptr& connection);

    // Notify listeners of a new message for pk
    void notify_listeners(const std::string& pk, const message_t& msg);

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_t& msg);

    /// Process message relayed from another SN from our swarm
    void process_push(const message_t& msg);

    /// Process incoming blob of messages: add to DB if new
    void process_push_all(std::shared_ptr<std::string> blob);

    bool is_pubkey_for_us(const std::string& pk) const;

    void swarm_timer_tick();

    std::vector<sn_record_t> get_snodes_by_pk(const std::string& pk);

    /// remove all data that doesn't belong to this swarm
    void purge_outdated();

    /// return all messages for a particular PK (in JSON)
    bool
    get_all_messages(std::vector<service_node::storage::Item>& all_entries);

    bool retrieve(const std::string& pubKey, const std::string& last_hash,
                  std::vector<service_node::storage::Item>& items);
};

} // namespace loki
