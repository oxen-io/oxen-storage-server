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

SwarmEvents Swarm::derive_swarm_events(uint64_t height, const swarms_t& swarms) const {
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

    if (new_swarm == INVALID_SWARM_ID) {
        if (cur_swarm_id_ != INVALID_SWARM_ID)
            log::warning(
                    logswarm,
                    "Leaving swarm {:#018x}: we are no longer an active Service Node",
                    cur_swarm_id_);
        else
            log::debug(logswarm, "Still not an active Service Node");

        // We are not in any swarm (or have been kicked out); nothing to do
        return events;
    }

    if (old_swarm == INVALID_SWARM_ID) {
        log::info(logcat, "Joined swarm {:#18x} (blk {})", new_swarm, height);
        // We were previously not in a swarm, which means we just got assigned to one, we need to
        // relay any of our messages belonging to the swarm
        events.new_swarm_members = events.our_swarm_members;
        events.new_swarm_members.erase(our_pk);
        return events;
    }

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
        log::info(
                logcat,
                "Changed from {:018x} {}to {:018x} (blk {})",
                old_swarm,
                new_swarm,
                height,
                events.dissolved ? "(dissolved) " : "");

        // If our old swarm is still alive then that means we got moved out of it, and so there's
        // nothing for us to do because the remaining swarm members will continue to administer the
        // old swarm, and whatever swarm we just moved into (possibly a new one) will have messages
        // pushed to it by other network nodes.
        return events;
    }

    /// --- WE are still in the same swarm if we reach here ---

    /// See if anyone joined our swarm: if so, we need to push messages to them:
    for (auto it : events.our_swarm_members)
        if (members_.count(it) == 0)
            events.new_swarm_members.insert(it);
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
        uint64_t height,
        swarms_t&& swarms,
        const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    std::lock_guard lock{network.mut_};

    auto events = derive_swarm_events(height, swarms);
    if (db_was_initially_empty_with_swarm_id == INVALID_SWARM_ID)
        db_was_initially_empty_with_swarm_id = events.our_swarm_id;

    if (events.our_swarm_id != INVALID_SWARM_ID) {
        for (const auto& pk : events.new_swarm_members)
            log::info(logswarm, "New SN joining our swarm: {}", pk);

        for (auto swarm : events.new_swarms)
            log::info(logswarm, "New network swarm: {}", swarm);

        // Remove members that are no longer in the swarm from our runtime state
        for (auto it = members_.begin(); it != members_.end();) {
            if (events.our_swarm_members.find(it->first) == events.our_swarm_members.end())
                it = members_.erase(it);
            else
                it++;
        }

        // TODO: Remove the versions checks below after everyone migrates their SQL DB to v1. The
        // version checks gate the new behaviour where this SS will request a dump of the swarm
        // member's DB to synchronise new messages.
        //
        // When a SS upgrades to this version, their DB is initially set to v0 and all the prior
        // active service nodes that upgrade will have the chain synchronised and their SS's sitting
        // in the correct swarm. We do _not_ want those storage servers to, on upgrade, request a DB
        // dump of all the messages from each swarm peer as they are (presumably) relatively synced.
        //
        // The SS's on v0 don't persist the swarm state to the DB, so on startup they always
        // re-bootstrap the state of their swarms. This populates the new-swarm-members array and
        // hence triggers the extraneous swarm dump.
        //
        // The version gate protects against that happening to all the individual nodes on upgrade.
        // Once all v0 SS's upgrade, the DB will be marked v1. From that point, swarms are persisted
        // onto disk and so any SS's that appear in the new-swarm-members array is _actually_ a new
        // SS and we _should_ request a DB a dump from them to synchronise messages they might have
        // for us.
        //
        // New incoming nodes in general are going to end up having 0 messages for us if they are
        // joining the network for the first time.
        //
        // If we are joining a swarm, then, all the members of the swarm are in the
        // new-swarm-members array and we will request a DB dump from them.
        //
        // In a swarm dissolving case, then, these new nodes will have a chunk of messages in the
        // adjacent message space that belong to this swarm they are merging into. That is handled
        // here.

        // Add members from the swarm that are missing from our runtime state and request a DB dump
        // from them to ensure we have all the messages they have that we don't.
        for (auto it : events.new_swarm_members) {
            auto& pair = members_[it];
            if (oxenss::tmp_init_db_version == 1) {
                if (pair.our_ss_requested_db_dump == SwarmRequestedDBDump::Nil)
                    pair.our_ss_requested_db_dump = SwarmRequestedDBDump::NeedsToRequest;
            }
        }

        // If the DB was empty on startup then we mark all swarm members as peers that we need to
        // request a DB dump from. Note we only do this if the swarm matches the initial swarm we
        // were in when the DB was queried. We might have changed swarms since startup, in which
        // case, the above branch will already initiate a DB dump request for us.
        //
        // This also covers the case where someone drops the messages table and restarts the SS, we
        // need to resync all the messages from everyone in the swarm.
        if (db_was_initially_empty_with_swarm_id == events.our_swarm_id &&
            !db_was_initially_empty_handled) {
            db_was_initially_empty_handled = true;
            for (auto& it : members_) {
                if (it.second.our_ss_requested_db_dump == SwarmRequestedDBDump::Nil) {
                    it.second.our_ss_requested_db_dump = SwarmRequestedDBDump::NeedsToRequest;
                }
            }
        }
    }

    oxenss::tmp_init_db_version = 1;  // Disable after the first swarm update

    cur_swarm_id_ = events.our_swarm_id;

    network.update_swarms(std::move(swarms), new_contacts);

    return events;
}

bool Swarm::is_pubkey_for_us(const user_pubkey& pk) const {
    auto maybe_swarm = network.get_swarm_id_for(pk);
    return maybe_swarm && cur_swarm_id_ == *maybe_swarm;
}

std::map<crypto::legacy_pubkey, SwarmMemberState> Swarm::members() const {
    std::shared_lock lock{network.mut_};
    return members_;
}

// Returns a copy of all the other members of this swarm, not including this node.
std::map<crypto::legacy_pubkey, SwarmMemberState> Swarm::peers() const {
    auto peers = members();
    peers.erase(our_pk);
    return peers;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::legacy_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (const auto& it = members_.find(pk); it != members_.end())
        result = it->second;
    return result;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::x25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (auto lpk = network.contacts.lookup(pk))
        result = is_member(*lpk);
    return result;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::ed25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (auto lpk = network.contacts.lookup(pk))
        result = is_member(*lpk);
    return result;
}

SwarmMemberState* Swarm::is_member_locked(const crypto::legacy_pubkey& pk) {
    SwarmMemberState* result = nullptr;
    if (auto it = members_.find(pk); it != members_.end())
        result = &it->second;
    return result;
}

size_t Swarm::size() const {
    std::shared_lock lock{network.mut_};
    return members_.size();
}

std::set<crypto::legacy_pubkey> Swarm::extract_contact_pending_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    auto now = std::chrono::steady_clock::now();
    for (auto it = members_.begin(); it != members_.end(); it++) {
        SwarmMemberState& state = it->second;
        if (state.status != SwarmMemberStatus::ContactDetailsPending)
            continue;
        std::chrono::steady_clock::time_point& next_retry =
                it->second.check_contact_info_next_retry;
        if (now >= next_retry) {
            next_retry = now + NEW_SWARM_MEMBER_RETRY;
            const crypto::legacy_pubkey& pk = it->first;
            result.insert(pk);
        }
    }

    return result;
}

std::set<crypto::legacy_pubkey> Swarm::extract_contacts_needing_db_dump() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    for (auto& it : members_) {
        if (it.second.status == SwarmMemberStatus::Ready) {
            const crypto::legacy_pubkey& pk = it.first;
            if (it.second.their_ss_needs_db_dump) {
                it.second.their_ss_needs_db_dump = false;
                result.insert(pk);
            }
        }
    }

    return result;
}
}  // namespace oxenss::snode
