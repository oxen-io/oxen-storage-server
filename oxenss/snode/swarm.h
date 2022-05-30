#pragma once

#include <iostream>
#include <oxenmq/auth.h>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#include <oxenss/common/pubkey.h>
#include "sn_record.h"

namespace oxen::snode {

class ServiceNode;

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

struct SwarmInfo {
    swarm_id_t swarm_id;
    std::vector<sn_record> snodes;
};

struct block_update {
    std::vector<SwarmInfo> swarms;
    std::vector<sn_record> decommissioned_nodes;
    oxenmq::pubkey_set active_x25519_pubkeys;
    uint64_t height;
    std::string block_hash;
    int hardfork;
    int snode_revision;
    bool unchanged = false;
};

void debug_print(std::ostream& os, const block_update& bu);

// Returns a reference to the SwarmInfo member of `all_swarms` for the given user pub.  Returns
// a reference to a null SwarmInfo with swarm_id set to INVALID_SWARM_ID on error (which will
// only happen if there are no swarms at all).
const SwarmInfo& get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms, const user_pubkey_t& pk);

// Takes a swarm update, returns the number of active SN entries with missing
// IP/port/ed25519/x25519 data and the total number of entries.  (We don't include
// decommissioned nodes in either count).
std::pair<int, int> count_missing_data(const block_update& bu);

/// For every node in `swarms_to_keep`, this checks whether the node
/// exists in incoming `other_swarms` and has a new IP address.
/// If it does and the value is not "0.0.0.0", it updates the value for that node.
std::vector<SwarmInfo> apply_ips(
        const std::vector<SwarmInfo>& swarms_to_keep, const std::vector<SwarmInfo>& other_swarms);

/// Maps a pubkey into a 64-bit "swarm space" value; the swarm you belong to is whichever one
/// has a swarm id closest to this pubkey-derived value.
uint64_t pubkey_to_swarm_space(const user_pubkey_t& pk);

struct SwarmEvents {
    /// our (potentially new) swarm id
    swarm_id_t our_swarm_id;
    /// whether our swarm got dissolved and we
    /// need to salvage our stale data
    bool dissolved = false;
    /// detected new swarms that need to be bootstrapped
    std::vector<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::vector<sn_record> new_snodes;
    /// our swarm members 
    std::vector<sn_record> our_swarm_members;
};

class Swarm {

    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;
    /// Note: this excludes the "dummy" swarm
    std::vector<SwarmInfo> all_valid_swarms_;
    sn_record our_address_;
    std::vector<sn_record> swarm_peers_;
    /// This includes decommissioned nodes
    std::unordered_map<crypto::legacy_pubkey, sn_record> all_funded_nodes_;
    std::unordered_map<crypto::ed25519_pubkey, crypto::legacy_pubkey> all_funded_ed25519_;
    std::unordered_map<crypto::x25519_pubkey, crypto::legacy_pubkey> all_funded_x25519_;

    /// Check if `sid` is an existing (active) swarm
    bool is_existing_swarm(swarm_id_t sid) const;

  public:
    Swarm(sn_record address) : our_address_(address) {}

    ~Swarm();

    /// Extract relevant information from incoming swarm composition
    SwarmEvents derive_swarm_events(const std::vector<SwarmInfo>& swarms) const;

    /// Update swarm state according to `events`. If not `is_active`
    /// only update the list of all nodes
    void update_state(
            const std::vector<SwarmInfo>& swarms,
            const std::vector<sn_record>& decommissioned,
            const SwarmEvents& events,
            bool is_active);

    void apply_swarm_changes(const std::vector<SwarmInfo>& new_swarms);

    bool is_pubkey_for_us(const user_pubkey_t& pk) const;

    const std::vector<sn_record>& other_nodes() const { return swarm_peers_; }

    const std::vector<SwarmInfo>& all_valid_swarms() const { return all_valid_swarms_; }

    const sn_record& our_address() const { return our_address_; }

    swarm_id_t our_swarm_id() const { return cur_swarm_id_; }

    bool is_valid() const { return cur_swarm_id_ != INVALID_SWARM_ID; }

    void set_swarm_id(swarm_id_t sid);

    const std::unordered_map<crypto::legacy_pubkey, sn_record>& all_funded_nodes() const {
        return all_funded_nodes_;
    }

    // Get the node with public key `pk` if exists; these search *all* fully-funded SNs
    // (including decommissioned ones), not just the current swarm.
    std::optional<sn_record> find_node(const crypto::legacy_pubkey& pk) const;
    std::optional<sn_record> find_node(const crypto::ed25519_pubkey& pk) const;
    std::optional<sn_record> find_node(const crypto::x25519_pubkey& pk) const;
};

}  // namespace oxen::snode
