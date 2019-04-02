#pragma once

#include <Database.hpp>
#include <fstream>
#include <iostream>
#include <memory>

#include <boost/asio.hpp>
#include <boost/optional.hpp>

#include "common.h"
#include "swarm.h"

static constexpr uint16_t SNODE_PORT = 8080;

class Database;

namespace service_node {
namespace storage {
class Item;
} // namespace storage
} // namespace service_node

namespace loki {

/// message as received by client
struct message_t {

    std::string pk_;
    std::string text_;
    std::string hash_;
    uint64_t ttl_;
    uint64_t timestamp_;
    std::string nonce_;

    message_t(const std::string& pk, const std::string& text, const std::string& hash, uint64_t ttl,
              uint64_t timestamp, const std::string& nonce)
        : pk_(pk), text_(text), hash_(hash), ttl_(ttl), timestamp_(timestamp),
          nonce_(nonce) {}
};

struct saved_message_t {

    std::string hash_;
    std::string pk_;
    std::string text_;

    saved_message_t(std::string hash, const char* pk, const char* text)
        : hash_(hash), pk_(pk), text_(text) {}
};

using message_ptr = std::shared_ptr<message_t>;

class Swarm;

/// All service node logic that is not network-specific
class ServiceNode {

    boost::asio::io_context& ioc_;

    std::unique_ptr<Swarm> swarm_;
    std::unique_ptr<Database> db_;

    uint16_t our_port_;

    sn_record_t our_address_;

    boost::asio::steady_timer update_timer_;

    void push_message(const message_ptr msg);

    void save_if_new(const message_ptr msg);

    /// request swarm info from the blockchain
    void update_swarms();

    void on_swarm_update(all_swarms_t all_swarms);

    void bootstrap_peers(const std::vector<sn_record_t>& peers) const;

    void bootstrap_swarms(const std::vector<swarm_id_t>& swarms) const;

    /// Distribute all our data to where it belongs
    /// (called when our old node got dissolved)
    void salvage_data() const;

    /// used on push and on swarm bootstrapping
    void relay_one(const message_ptr msg, sn_record_t address) const;

    /// used for SN bootstrapping
    void relay_batch(const std::string& data, sn_record_t address) const;

    /// return all messages serialized
    std::string serialize_all() const;

  public:
    ServiceNode(boost::asio::io_context& ioc, uint16_t port,
                const std::string& identityPath, const std::string& dbLocation);

    ~ServiceNode();

    /// Process message received from a client, return false if not in a swarm
    bool process_store(const message_ptr msg);

    /// Process message relayed from another SN from our swarm
    void process_push(const message_ptr msg);

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
