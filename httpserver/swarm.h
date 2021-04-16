#pragma once

#include <iostream>
#include <oxenmq/auth.h>
#include <string>
#include <vector>

#include "oxen_common.h"
#include "sn_record.h"

namespace boost::asio {
class io_context;
} // namespace boost::asio

namespace oxen {

class ServiceNode;

struct SwarmInfo {
    swarm_id_t swarm_id;
    std::vector<sn_record_t> snodes;
};

using all_swarms_t = std::vector<SwarmInfo>;

struct block_update_t {
    all_swarms_t swarms;
    std::vector<sn_record_t> decommissioned_nodes;
    oxenmq::pubkey_set active_x25519_pubkeys;
    uint64_t height;
    std::string block_hash;
    int hardfork;
    bool unchanged = false;
};

void debug_print(std::ostream& os, const block_update_t& bu);

swarm_id_t get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms,
                           const user_pubkey_t& pk);

// Takes a swarm update, returns the number of active SN entries with missing
// IP/port/ed25519/x25519 data and the total number of entries.  (We don't include
// decommissioned nodes in either count).
std::pair<int, int> count_missing_data(const block_update_t& bu);

/// For every node in `swarms_to_keep`, this checks whether the node
/// exists in incoming `other_swarms` and has a new IP address.
/// If it does and the value is not "0.0.0.0", it updates the value for that node.
auto apply_ips(const all_swarms_t& swarms_to_keep,
               const all_swarms_t& other_swarms) -> all_swarms_t;

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
    std::unordered_map<legacy_pubkey, sn_record_t> all_funded_nodes_;
    std::unordered_map<ed25519_pubkey, legacy_pubkey> all_funded_ed25519_;
    std::unordered_map<x25519_pubkey, legacy_pubkey> all_funded_x25519_;

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

    const std::vector<sn_record_t>& other_nodes() const { return swarm_peers_; }

    const std::vector<SwarmInfo>& all_valid_swarms() const {
        return all_valid_swarms_;
    }

    const sn_record_t& our_address() const { return our_address_; }

    swarm_id_t our_swarm_id() const { return cur_swarm_id_; }

    bool is_valid() const { return cur_swarm_id_ != INVALID_SWARM_ID; }

    void set_swarm_id(swarm_id_t sid);

    const std::unordered_map<legacy_pubkey, sn_record_t>& all_funded_nodes() const {
        return all_funded_nodes_;
    }

    // Get the node with public key `pk` if exists; these search *all* fully-funded SNs (including
    // decommissioned ones), not just the current swarm.
    std::optional<sn_record_t> find_node(const legacy_pubkey& pk) const;
    std::optional<sn_record_t> find_node(const ed25519_pubkey& pk) const;
    std::optional<sn_record_t> find_node(const x25519_pubkey& pk) const;
};

} // namespace oxen
