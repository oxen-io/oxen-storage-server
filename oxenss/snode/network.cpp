#include "network.h"
#include <oxenmq/oxenmq.h>
#include <cassert>
#include <iterator>
#include <ranges>
#include "oxenc/endian.h"
#include "oxenss/crypto/keys.h"
#include "swarm.h"

namespace oxenss::snode {

Network::Network(oxenmq::OxenMQ& omq) : contacts{omq} {}

uint64_t Network::pubkey_to_swarm_space(const user_pubkey& pk) {
    const auto bytes = pk.raw();
    assert(bytes.size() == 32);

    uint64_t res = 0;
    for (size_t i = 0; i < bytes.size(); i += 8)
        res ^= oxenc::load_big_to_host<uint64_t>(bytes.data() + i);

    return res;
}

swarms_t::const_iterator Network::_find_swarm_for(const user_pubkey& pk) const {
    if (swarms_.empty())
        return swarms_.end();
    if (swarms_.size() == 1)
        return swarms_.begin();

    const uint64_t swarm_pos = pubkey_to_swarm_space(pk);

    // Find the right boundary, i.e. first swarm with swarm_id >= res
    auto right_it = swarms_.lower_bound(swarm_pos);

    if (right_it == swarms_.end())
        // swarm_pos is > the top swarm_id, meaning it is big and in the wrapping space between last
        // and first elements.
        right_it = swarms_.begin();

    // Our "left" is the swarm just before right (with wraparound, if right is the first swarm)
    auto left_it = std::prev(right_it == swarms_.begin() ? swarms_.end() : right_it);

    // So now we know that this pubkey is somewhere in [left, right], so our swarm is whichever of
    // those is closest to us, with intentional uint64_t overflow here to properly measure distance
    // across the max-uint64_t boundary.
    uint64_t dright = right_it->first - swarm_pos;
    uint64_t dleft = swarm_pos - left_it->first;

    return dright < dleft ? right_it : left_it;
}

std::optional<swarm_id_t> Network::get_swarm_id_for(const user_pubkey& pk) const {
    std::shared_lock lock{mut_};
    if (auto it = _find_swarm_for(pk); it != swarms_.end())
        return it->first;
    return std::nullopt;
}

std::optional<std::pair<swarm_id_t, std::set<crypto::legacy_pubkey>>> Network::get_swarm_for(
        const user_pubkey& pk) const {
    std::shared_lock lock{mut_};
    if (auto it = _find_swarm_for(pk); it != swarms_.end())
        return *it;
    return std::nullopt;
}

std::optional<std::set<crypto::legacy_pubkey>> Network::get_swarm(swarm_id_t swid) const {
    std::shared_lock lock{mut_};
    if (auto it = swarms_.find(swid); it != swarms_.end())
        return it->second;
    return std::nullopt;
}

void Network::update_swarms(
        swarms_t&& new_swarms, const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    // We are only called from Swarm, which already holds the lock:
    // std::unique_lock lock{mut_};

    std::set<crypto::legacy_pubkey> old_pks = contacts.get_pubkeys();
    auto new_pks = std::views::keys(new_contacts);
    std::vector<crypto::legacy_pubkey> removed;
    std::set_difference(
            old_pks.begin(),
            old_pks.end(),
            new_pks.begin(),
            new_pks.end(),
            std::back_inserter(removed));

    int contact_changes = contacts.update_and_erase(
            new_contacts.begin(), new_contacts.end(), removed.begin(), removed.end());

    if (all_nodes_blob_ && (contact_changes || swarms_ != new_swarms))
        all_nodes_blob_.reset();

    swarms_ = std::move(new_swarms);
}

static constexpr size_t PER_SNODE_BLOB_SIZE = 51;
static_assert(
        sizeof(crypto::ed25519_pubkey) + sizeof(uint64_t) + sizeof(oxen::quic::ipv4) +
                sizeof(uint16_t) + sizeof(uint16_t) + 3 ==
        PER_SNODE_BLOB_SIZE);

std::shared_ptr<std::vector<std::byte>> Network::all_nodes_blob() const {
    {
        std::shared_lock lock{mut_};
        if (all_nodes_blob_)
            return all_nodes_blob_;
    }

    std::unique_lock lock{mut_, std::defer_lock};
    std::shared_lock c_lock{contacts, std::defer_lock};
    std::lock(lock, c_lock);

    size_t snode_count = 0;
    for (auto& [swid, members] : swarms_)
        snode_count += members.size();

    auto blob = std::make_shared<std::vector<std::byte>>();
    blob->resize(snode_count * PER_SNODE_BLOB_SIZE);
    auto* ptr = blob->data();
    for (auto& [swid, members] : swarms_) {
        const uint64_t big_swid = oxenc::host_to_big(swid);
        for (auto& pk : members) {
            auto* c = contacts.find_locked(pk);
            if (!c || !c->pubkey_ed25519)
                continue;
#ifndef NDEBUG
            auto* start_ptr = ptr;
#endif
            std::memcpy(ptr, c->pubkey_ed25519.data(), c->pubkey_ed25519.size());
            ptr += c->pubkey_ed25519.size();
            std::memcpy(ptr, &big_swid, sizeof(big_swid));
            ptr += sizeof(big_swid);
            oxenc::write_host_as_big(c->ip.addr, ptr);
            ptr += sizeof(c->ip.addr);
            oxenc::write_host_as_big(c->https_port, ptr);
            ptr += sizeof(c->https_port);
            oxenc::write_host_as_big(c->omq_quic_port, ptr);
            ptr += sizeof(c->omq_quic_port);
            for (auto v16 : c->version)
                *ptr++ = static_cast<std::byte>(std::min<uint16_t>(v16, 255));
            assert(ptr == start_ptr + PER_SNODE_BLOB_SIZE);
        }
    }

    // If we skipped some uncontactable nodes then we might have overallocated:
    blob->resize(ptr - blob->data());

    all_nodes_blob_ = blob;
    return blob;
}

}  // namespace oxenss::snode
