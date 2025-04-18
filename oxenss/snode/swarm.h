#pragma once

#include <chrono>
#include <set>
#include <unordered_map>

#include "network.h"
#include "oxenss/crypto/keys.h"

namespace oxenss::snode {

using namespace std::literals;

class ServiceNode;

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

struct SwarmEvents {
    /// our (potentially new) swarm id
    swarm_id_t our_swarm_id;
    /// whether our swarm got dissolved and we need to salvage our stale data
    bool dissolved = false;
    /// detected new swarms that need to be bootstrapped
    std::set<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::set<crypto::legacy_pubkey> new_swarm_members;
    /// our swarm members 
    std::set<crypto::legacy_pubkey> our_swarm_members;
};

// How often we wait, after returning a pending new member, before we return the member again from
// `extract_new_members()`.
constexpr auto NEW_SWARM_MEMBER_RETRY = 30s;

class Swarm {
    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;

    std::set<crypto::legacy_pubkey> members_;  // includes `our_pk`, when we are in a swarm.

    // Pubkeys of new members into our swarm who we haven't yet established communications with;
    // once we do, we push all our swarm's messages to them.  The value is the earliest timestamp at
    // which we should next try contacting them, or nullopt if we have confirmed contact and can now
    // send the data.
    std::unordered_map<crypto::legacy_pubkey, std::optional<std::chrono::steady_clock::time_point>>
            pending_new_members_;

    // Extract relevant information from incoming swarm composition.
    SwarmEvents derive_swarm_events(const swarms_t& swarms) const;

  public:
    Network& network;
    const crypto::legacy_pubkey our_pk;

    Swarm(Network& network, const crypto::legacy_pubkey& our_pk) :
            network{network}, our_pk{our_pk} {}

    ~Swarm();

    /// Update swarm state; this takes care of updating both this swarm itself, and propagates the
    /// general network swarm changes to the Network object (including contacts) as well.
    SwarmEvents update_swarms(
            swarms_t&& swarms, const std::map<crypto::legacy_pubkey, contact>& new_contacts);

    bool is_pubkey_for_us(const user_pubkey& pk) const;

    // Returns a copy of all the members of this swarm, including this node.
    std::set<crypto::legacy_pubkey> members() const;

    // Returns a copy of all the other members of this swarm, not including this node.
    std::set<crypto::legacy_pubkey> peers() const;

    // Returns true if the given pubkey is recognized as a member of this swarm.
    bool is_member(const crypto::legacy_pubkey& pk) const;
    bool is_member(const crypto::x25519_pubkey& pk) const;
    bool is_member(const crypto::ed25519_pubkey& pk) const;

    // Returns the size of this swarm (including this node).
    size_t size() const;

    // Resets the timer and returns the pubkeys of any new swarm members that are due to be
    // contacted to push swarm messages to.
    std::set<crypto::legacy_pubkey> extract_pending_members();

    // Marks a pending member as ready, so that it is returned by the next call to
    // `extract_ready_members()`, and is no longer returned by `extract_pending_members()`.
    void set_member_ready(const crypto::legacy_pubkey& pk);

    // Extracts any "ready" members (that is, those that were pending and then marked ready with
    // `set_member_ready`), returning them and removing them from the pending members list.
    std::set<crypto::legacy_pubkey> extract_ready_members();

    swarm_id_t our_swarm_id() const {
        std::shared_lock lock{network.mut_};
        return cur_swarm_id_;
    }

    bool is_valid() const { return our_swarm_id() != INVALID_SWARM_ID; }
};

}  // namespace oxenss::snode
