#pragma once

#include <iostream>
#include <lokimq/auth.h>
#include <string>
#include <vector>

#include "loki_common.h"

namespace boost {
namespace asio {
class io_context;
}
} // namespace boost

namespace loki {

class ServiceNode;

struct SwarmInfo {
    swarm_id_t swarm_id;
    std::vector<sn_record_t> snodes;
};

using all_swarms_t = std::vector<SwarmInfo>;

struct block_update_t {
    all_swarms_t swarms;
    std::vector<sn_record_t> decommissioned_nodes;
    lokimq::pubkey_set active_x25519_pubkeys;
    uint64_t height;
    std::string block_hash;
    int hardfork;
    bool unchanged = false;
};

void debug_print(std::ostream& os, const block_update_t& bu);

swarm_id_t get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms,
                           const user_pubkey_t& pk);

struct SwarmEvents {

    /// our (potentially new) swarm id
    swarm_id_t our_swarm_id;
    /// whether our swarm got dissolved and we
    /// need to salvage our stale data
    bool dissolved = false;
    /// detected new swarms that need to be bootstrapped
    std::vector<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::vector<sn_record_t> new_snodes;
    /// our swarm members 
    std::vector<sn_record_t> our_swarm_members;
};

class Swarm {

    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;
    /// Note: this excludes the "dummy" swarm
    std::vector<SwarmInfo> all_valid_swarms_;
    sn_record_t our_address_;
    std::vector<sn_record_t> swarm_peers_;
    /// This includes decommissioned nodes
    std::vector<sn_record_t> all_funded_nodes_;

    /// Check if `sid` is an existing (active) swarm
    bool is_existing_swarm(swarm_id_t sid) const;

  public:
    Swarm(sn_record_t address) : our_address_(address) {}

    ~Swarm();

    /// Extract relevant information from incoming swarm composition
    SwarmEvents derive_swarm_events(const all_swarms_t& swarms) const;

    /// Update swarm state according to `events`. If not `is_active`
    /// only update the list of all nodes
    void update_state(const all_swarms_t& swarms,
                      const std::vector<sn_record_t>& decommissioned,
                      const SwarmEvents& events, bool is_active);

    void apply_swarm_changes(const all_swarms_t& new_swarms);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    /// Whether `sn_address` is found in any of the swarms, including the
    /// dummy swarm with decommissioned nodes
    bool is_fully_funded_node(const std::string& sn_address) const;

    const std::vector<sn_record_t>& other_nodes() const;

    const std::vector<SwarmInfo>& all_valid_swarms() const {
        return all_valid_swarms_;
    }

    swarm_id_t our_swarm_id() const { return cur_swarm_id_; }

    bool is_valid() const { return cur_swarm_id_ != INVALID_SWARM_ID; }

    void set_swarm_id(swarm_id_t sid);

    // Select a node from all existing nodes (excluding us); throws if there is
    // no other nodes
    std::optional<sn_record_t> choose_funded_node() const;

    // TEMPORARY (TODO: change to finding by x25519 PK)
    std::optional<sn_record_t> find_node_by_port(uint16_t port) const;

    // Get the node with public key `pk` if exists
    std::optional<sn_record_t> get_node_by_pk(const sn_pub_key_t& pk) const;

    std::optional<sn_record_t>
    find_node_by_ed25519_pk(const sn_pub_key_t& address) const;

    std::optional<sn_record_t>
    find_node_by_x25519_bin(const sn_pub_key_t& address) const;
};

} // namespace loki
