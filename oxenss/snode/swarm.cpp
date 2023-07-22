#include "swarm.h"
#include "service_node.h"
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>

#include <cstdlib>
#include <ostream>
#include <unordered_map>
#include <oxenc/endian.h>

namespace oxen::snode {

static auto logcat = log::Cat("snode");

static bool swarm_exists(const std::vector<SwarmInfo>& all_swarms, const swarm_id_t& swarm) {
    const auto it =
            std::find_if(all_swarms.begin(), all_swarms.end(), [&swarm](const SwarmInfo& si) {
                return si.swarm_id == swarm;
            });

    return it != all_swarms.end();
}

Swarm::~Swarm() = default;

bool Swarm::is_existing_swarm(swarm_id_t sid) const {
    return std::any_of(
            all_valid_swarms_.begin(),
            all_valid_swarms_.end(),
            [sid](const SwarmInfo& cur_swarm_info) { return cur_swarm_info.swarm_id == sid; });
}

SwarmEvents Swarm::derive_swarm_events(const std::vector<SwarmInfo>& swarms) const {
    SwarmEvents events = {};

    const auto our_swarm_it =
            std::find_if(swarms.begin(), swarms.end(), [this](const SwarmInfo& swarm_info) {
                const auto& snodes = swarm_info.snodes;
                return std::find(snodes.begin(), snodes.end(), our_address_) != snodes.end();
            });

    if (our_swarm_it == swarms.end()) {
        // We are not in any swarm, nothing to do
        events.our_swarm_id = INVALID_SWARM_ID;
        return events;
    }

    const auto& new_swarm_snodes = our_swarm_it->snodes;
    const auto new_swarm_id = our_swarm_it->swarm_id;

    events.our_swarm_id = new_swarm_id;
    events.our_swarm_members = new_swarm_snodes;

    if (cur_swarm_id_ == INVALID_SWARM_ID) {
        // Only started in a swarm, nothing to do at this stage
        return events;
    }

    if (cur_swarm_id_ != new_swarm_id) {
        // Got moved to a new swarm
        if (!swarm_exists(swarms, cur_swarm_id_)) {
            // Dissolved, new to push all our data to new swarms
            events.dissolved = true;
        }

        // If our old swarm is still alive, there is nothing for us to do
        return events;
    }

    /// --- WE are still in the same swarm if we reach here ---

    /// See if anyone joined our swarm
    for (const auto& sn : new_swarm_snodes) {
        const auto it = std::find(swarm_peers_.begin(), swarm_peers_.end(), sn);

        if (it == swarm_peers_.end() && sn != our_address_) {
            events.new_snodes.push_back(sn);
        }
    }

    /// See if there are any new swarms

    for (const auto& swarm_info : swarms)
        if (!is_existing_swarm(swarm_info.swarm_id))
            events.new_swarms.push_back(swarm_info.swarm_id);

    /// NOTE: need to be careful and make sure we don't miss any
    /// swarm update (e.g. if we don't update frequently enough)

    return events;
}

void Swarm::set_swarm_id(swarm_id_t sid) {
    if (sid == INVALID_SWARM_ID) {
        log::warning(logcat, "We are not currently an active Service Node");
    } else {
        if (cur_swarm_id_ == INVALID_SWARM_ID) {
            log::info(logcat, "EVENT: started SN in swarm: 0x{}", util::int_to_string(sid, 16));
        } else if (cur_swarm_id_ != sid) {
            log::info(
                    logcat,
                    "EVENT: got moved into a new swarm: 0x{}",
                    util::int_to_string(sid, 16));
        }
    }

    cur_swarm_id_ = sid;
}

void preserve_ips(std::vector<SwarmInfo>& new_swarms, const std::vector<SwarmInfo>& old_swarms) {

    std::unordered_map<crypto::legacy_pubkey, sn_record*> missing;

    for (auto& [swarm_id, snodes] : new_swarms)
        for (auto& snode : snodes)
            if (snode.ip == "0.0.0.0" && snode.port == 0 && snode.omq_port == 0)
                missing.emplace(snode.pubkey_legacy, &snode);

    if (missing.empty())
        return;

    for (auto& [swarm_id, snodes] : old_swarms) {
        for (auto& snode : snodes) {
            auto it = missing.find(snode.pubkey_legacy);
            if (it == missing.end())
                continue;
            if (snode.ip != "0.0.0.0" && snode.port != 0 && snode.omq_port != 0) {
                it->second->ip = snode.ip;
                it->second->port = snode.port;
                it->second->omq_port = snode.omq_port;
            }
            missing.erase(it);
            if (missing.empty())
                return;
        }
    }
}

void Swarm::apply_swarm_changes(std::vector<SwarmInfo>&& new_swarms) {
    log::trace(logcat, "Applying swarm changes");

    preserve_ips(new_swarms, all_valid_swarms_);
    all_valid_swarms_ = std::move(new_swarms);
}

void Swarm::update_state(
        std::vector<SwarmInfo>&& swarms,
        const std::vector<sn_record>& decommissioned,
        const SwarmEvents& events,
        bool active) {
    if (active) {
        // The following only makes sense for active nodes in a swarm

        if (events.dissolved) {
            log::info(logcat, "EVENT: our old swarm got DISSOLVED!");
        }

        for (const sn_record& sn : events.new_snodes) {
            log::info(logcat, "EVENT: detected new SN: {}", sn.pubkey_legacy);
        }

        for (swarm_id_t swarm : events.new_swarms) {
            log::info(logcat, "EVENT: detected a new swarm: {}", swarm);
        }

        apply_swarm_changes(std::move(swarms));

        const auto& members = events.our_swarm_members;

        /// sanity check
        if (members.empty())
            return;

        swarm_peers_.clear();
        swarm_peers_.reserve(members.size() - 1);

        std::copy_if(
                members.begin(),
                members.end(),
                std::back_inserter(swarm_peers_),
                [this](const sn_record& record) { return record != our_address_; });
    }

    // Store a copy of every node in a separate data structure
    all_funded_nodes_.clear();
    all_funded_ed25519_.clear();
    all_funded_x25519_.clear();

    for (const auto& si : all_valid_swarms_) {
        for (const auto& sn : si.snodes) {
            all_funded_nodes_.emplace(sn.pubkey_legacy, sn);
        }
    }

    for (const auto& sn : decommissioned) {
        all_funded_nodes_.emplace(sn.pubkey_legacy, sn);
    }

    for (const auto& [pk, sn] : all_funded_nodes_) {
        all_funded_ed25519_.emplace(sn.pubkey_ed25519, pk);
        all_funded_x25519_.emplace(sn.pubkey_x25519, pk);
    }
}

std::optional<sn_record> Swarm::find_node(const crypto::legacy_pubkey& pk) const {
    if (auto it = all_funded_nodes_.find(pk); it != all_funded_nodes_.end())
        return it->second;
    return std::nullopt;
}

std::optional<sn_record> Swarm::find_node(const crypto::ed25519_pubkey& pk) const {
    if (auto it = all_funded_ed25519_.find(pk); it != all_funded_ed25519_.end())
        return find_node(it->second);
    return std::nullopt;
}

std::optional<sn_record> Swarm::find_node(const crypto::x25519_pubkey& pk) const {
    if (auto it = all_funded_x25519_.find(pk); it != all_funded_x25519_.end())
        return find_node(it->second);
    return std::nullopt;
}

uint64_t pubkey_to_swarm_space(const user_pubkey& pk) {
    const auto bytes = pk.raw();
    assert(bytes.size() == 32);

    uint64_t res = 0;
    for (size_t i = 0; i < 4; i++) {
        uint64_t buf;
        std::memcpy(&buf, bytes.data() + i * 8, 8);
        res ^= buf;
    }
    oxenc::big_to_host_inplace(res);

    return res;
}

bool Swarm::is_pubkey_for_us(const user_pubkey& pk) const {
    auto* swarm = get_swarm_by_pk(all_valid_swarms_, pk);
    return swarm && cur_swarm_id_ == swarm->swarm_id;
}

const SwarmInfo* get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms, const user_pubkey& pk) {

    if (all_swarms.empty())
        return nullptr;

    assert(std::is_sorted(all_swarms.begin(), all_swarms.end()));
    assert(all_swarms.back().swarm_id != INVALID_SWARM_ID);

    if (all_swarms.size() == 1)
        return &all_swarms.front();

    const uint64_t res = pubkey_to_swarm_space(pk);

    // NB: this code used to be far more convoluted by trying to accommodate the INVALID_SWARM_ID
    // value, but that was wrong (because pubkeys map to the *full* uint64_t range, including
    // INVALID_SWARM_ID), more complicated, and didn't calculate distances properly when wrapping
    // around (in generally, but catastrophically for the INVALID_SWARM_ID value).

    // Find the right boundary, i.e. first swarm with swarm_id >= res
    auto right_it = std::lower_bound(
            all_swarms.begin(), all_swarms.end(), res, [](const SwarmInfo& s, uint64_t v) {
                return s.swarm_id < v;
            });

    if (right_it == all_swarms.end())
        // res is > the top swarm_id, meaning it is big and in the wrapping space between last and
        // first elements.
        right_it = all_swarms.begin();

    // Our "left" is the one just before that (with wraparound, if right is the first swarm)
    auto left_it = std::prev(right_it == all_swarms.begin() ? all_swarms.end() : right_it);

    uint64_t dright = right_it->swarm_id - res;
    uint64_t dleft = res - left_it->swarm_id;

    return &*(dright < dleft ? right_it : left_it);
}

std::pair<int, int> count_missing_data(const block_update& bu) {
    auto result = std::make_pair(0, 0);
    auto& [missing, total] = result;

    for (auto& swarm : bu.swarms) {
        for (auto& snode : swarm.snodes) {
            total++;
            if (snode.ip.empty() || snode.ip == "0.0.0.0" || !snode.port || !snode.omq_port ||
                !snode.pubkey_ed25519 || !snode.pubkey_x25519) {
                missing++;
            }
        }
    }
    return result;
}

}  // namespace oxen::snode
