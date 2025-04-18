#include "swarm.h"
#include "oxenss/crypto/keys.h"
#include "service_node.h"
#include <oxenss/logging/oxen_logger.h>
#include <chrono>
#include <oxenss/utils/string_utils.hpp>

#include <algorithm>
#include <cstdlib>
#include <ranges>

namespace oxenss::snode {

static auto logcat = log::Cat("snode");
static auto logswarm = log::Cat("swarm");

Swarm::~Swarm() = default;

SwarmEvents Swarm::derive_swarm_events(const swarms_t& swarms) const {
    SwarmEvents events{};

    events.our_swarm_id = INVALID_SWARM_ID;
    for (auto& [id, members] : swarms) {
        if (members.count(our_pk)) {
            events.our_swarm_id = id;
            events.our_swarm_members = members;
            break;
        }
    }

    const auto& new_swarm = events.our_swarm_id;
    const auto& old_swarm = cur_swarm_id_;

    if (new_swarm == INVALID_SWARM_ID)
        // We are not in any swarm (or have been kicked out); nothing to do
        return events;

    if (old_swarm == INVALID_SWARM_ID)
        // We were previously not in a swarm, which means we just got assigned to one and so we have
        // nothing to do (other snodes will also see this and push messages to us).
        return events;

    if (old_swarm != new_swarm) {
        // Moved to a new swarm

        if (!network.swarms_.count(old_swarm)) {
            // The old swarm dissolved, which means we have a responsibility to push messages we are
            // still holding to whichever swarm(s) should now own them.  E.g. if swarms were
            // previously distributed:
            //
            //          A                B                 C
            // |.................|###############|!!!!!!!!!!!!!!!!!|
            //
            // and B gets dissolved then all the messages in swarm space ### need to get sent to
            // either A or C (depending on which swarm they land post-dissolution), like this:
            //
            //          A                                  C
            // |.................########|########!!!!!!!!!!!!!!!!!|
            events.dissolved = true;
        }

        // If our old swarm is still alive then that means we got moved out of it, and so there's
        // nothing for us to do because the remaining swarm members will continue to administer the
        // old swarm, and whatever swarm we just moved into (possibly a new one) will have messages
        // pushed to it by other network nodes.
        return events;
    }

    /// --- WE are still in the same swarm if we reach here ---

    /// See if anyone joined our swarm: if so, we need to push messages to them:
    std::set_difference(
            events.our_swarm_members.begin(),
            events.our_swarm_members.end(),
            members_.begin(),
            members_.end(),
            std::inserter(events.new_swarm_members, events.new_swarm_members.end()));
    events.new_swarm_members.erase(our_pk);

    // See if there are any new swarms, because if there are, we might need to push messages to them
    // if they happened to get set up adjascent to us.  E.g. if we are A (or C) here:
    //
    //          A                                  C
    // |.................########|########!!!!!!!!!!!!!!!!!|
    //
    // and B gets created in between us, then we need to push the `#` messages that we currently
    // hold to the new B swarm, so that the local swarm space ends up looking like this:
    //
    //          A                B                 C
    // |.................|###############|!!!!!!!!!!!!!!!!!|
    //
    // FIXME: currently we do this on any new swarm creation, but that seems excessive: we really
    // only need to worry about this if our boundary on either side changes.  (Most of the time it
    // won't because, with hundreds of swarms, most new swarms don't affect our swarm space).
    auto new_swarm_ids = std::views::keys(swarms);
    auto old_swarm_ids = std::views::keys(network.swarms_);
    std::set_difference(
            new_swarm_ids.begin(),
            new_swarm_ids.end(),
            old_swarm_ids.begin(),
            old_swarm_ids.end(),
            std::inserter(events.new_swarms, events.new_swarms.end()));

    return events;
}

SwarmEvents Swarm::update_swarms(
        swarms_t&& swarms, const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    std::lock_guard lock{network.mut_};

    auto events = derive_swarm_events(swarms);

    if (events.our_swarm_id == INVALID_SWARM_ID) {
        if (cur_swarm_id_ != INVALID_SWARM_ID)
            log::warning(
                    logswarm,
                    "Leaving swarm {:#018x}: we are no longer an active Service Node",
                    cur_swarm_id_);
        else
            log::debug(logswarm, "Still not an active Service Node");
    } else {

        if (cur_swarm_id_ == INVALID_SWARM_ID)
            log::info(logswarm, "SN now active, joining swarm {:#018x}", events.our_swarm_id);
        else if (cur_swarm_id_ != events.our_swarm_id)
            log::info(
                    logswarm,
                    "SN moving from swarm {:#018x} to swarm {:#018x}",
                    cur_swarm_id_,
                    events.our_swarm_id);

        // The following only make sense if we are active, i.e. still in a swarm

        if (events.dissolved)
            log::info(logswarm, "Our swarm ({:#018x}) got DISSOLVED!", cur_swarm_id_);

        for (const auto& pk : events.new_swarm_members) {
            log::info(logswarm, "New SN joining our swarm: {}", pk);
            pending_new_members_.emplace(pk, std::chrono::steady_clock::now());
        }

        for (auto swarm : events.new_swarms)
            log::info(logswarm, "New network swarm: {}", swarm);

        members_ = events.our_swarm_members;
    }

    cur_swarm_id_ = events.our_swarm_id;

    network.update_swarms(std::move(swarms), new_contacts);

    return events;
}

bool Swarm::is_pubkey_for_us(const user_pubkey& pk) const {
    auto maybe_swarm = network.get_swarm_id_for(pk);
    return maybe_swarm && cur_swarm_id_ == *maybe_swarm;
}

std::set<crypto::legacy_pubkey> Swarm::members() const {
    std::shared_lock lock{network.mut_};
    return members_;
}

// Returns a copy of all the other members of this swarm, not including this node.
std::set<crypto::legacy_pubkey> Swarm::peers() const {
    auto peers = members();
    peers.erase(our_pk);
    return peers;
}

bool Swarm::is_member(const crypto::legacy_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    return members_.count(pk);
}

bool Swarm::is_member(const crypto::x25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    if (auto lpk = network.contacts.lookup(pk))
        return members_.count(*lpk);
    return false;
}

bool Swarm::is_member(const crypto::ed25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    if (auto lpk = network.contacts.lookup(pk))
        return members_.count(*lpk);
    return false;
}

size_t Swarm::size() const {
    std::shared_lock lock{network.mut_};
    return members_.size();
}

std::set<crypto::legacy_pubkey> Swarm::extract_pending_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    auto now = std::chrono::steady_clock::now();
    for (auto it = pending_new_members_.begin(); it != pending_new_members_.end();) {
        auto& [pk, when] = *it;
        if (!members_.count(pk)) {
            // No longer in our swarm
            it = pending_new_members_.erase(it);
            continue;
        }

        if (when && *when <= now) {
            *when = now + NEW_SWARM_MEMBER_RETRY;
            result.insert(pk);
        }
        ++it;
    }

    return result;
}

std::set<crypto::legacy_pubkey> Swarm::extract_ready_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    for (auto it = pending_new_members_.begin(); it != pending_new_members_.end();) {
        auto& [pk, when] = *it;
        if (!members_.count(pk)) {
            // No longer in our swarm
            it = pending_new_members_.erase(it);
        } else if (!when) {
            // Found one that is marked ready, so steal it:
            result.insert(pk);
            it = pending_new_members_.erase(it);
        } else {
            ++it;
        }
    }

    return result;
}

void Swarm::set_member_ready(const crypto::legacy_pubkey& pk) {
    std::lock_guard lock{network.mut_};
    if (auto it = pending_new_members_.find(pk); it != pending_new_members_.end())
        it->second = std::nullopt;
}

}  // namespace oxenss::snode
