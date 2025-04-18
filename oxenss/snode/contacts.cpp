#include "contacts.h"

#include <oxenmq/oxenmq.h>
#include <mutex>
#include <ranges>

#include "oxenss/crypto/keys.h"

namespace oxenss::snode {

bool Contacts::_update(
        const crypto::legacy_pubkey& pk,
        const contact& c,
        oxenmq::pubkey_set& omq_add,
        oxenmq::pubkey_set& omq_rem) {
    auto [it, ins] = contacts.try_emplace(pk, c);
    bool changed = ins;
    if (!ins) {
        // Only replace the existing values if the new value has a non-0 value, so that we never
        // overwrite known values with unknown values

        auto& curr = it->second;
        if (c.pubkey_x25519 && curr.pubkey_x25519 != c.pubkey_x25519) {
            if (curr.pubkey_x25519) {
                omq_rem.insert(curr.pubkey_x25519.str());
                x_pk.erase(curr.pubkey_x25519);
            }
            omq_add.insert(c.pubkey_x25519.str());
            curr.pubkey_x25519 = c.pubkey_x25519;
            x_pk[c.pubkey_x25519] = pk;
            changed = true;
        }
        if (c.pubkey_ed25519 && curr.pubkey_ed25519 != c.pubkey_ed25519) {
            if (curr.pubkey_ed25519)
                ed_pk.erase(curr.pubkey_ed25519);
            curr.pubkey_ed25519 = c.pubkey_ed25519;
            ed_pk[c.pubkey_ed25519] = pk;
            changed = true;
        }

        auto upd = [&changed]<typename T>(T& cur, const T& val) {
            if (val != T{} && val != cur) {
                cur = val;
                changed = true;
            }
        };
        upd(curr.ip, c.ip);
        upd(curr.https_port, c.https_port);
        upd(curr.omq_quic_port, c.omq_quic_port);
        upd(curr.version, c.version);
    } else {
        if (c.pubkey_x25519) {
            x_pk[c.pubkey_x25519] = pk;
            omq_add.insert(c.pubkey_x25519.str());
        }
        if (c.pubkey_ed25519)
            ed_pk[c.pubkey_ed25519] = pk;
    }
    return changed;
}

bool Contacts::update(const crypto::legacy_pubkey& pk, const contact& c) {
    oxenmq::pubkey_set add, rem;
    std::unique_lock lock{mut};
    bool ret = _update(pk, c, add, rem);
    _update_omq_keys(add, rem);
    return ret;
}

bool Contacts::_erase(const crypto::legacy_pubkey& pk, oxenmq::pubkey_set& omq_rem) {
    auto it = contacts.find(pk);
    if (it == contacts.end())
        return false;
    if (it->second.pubkey_x25519) {
        omq_rem.insert(it->second.pubkey_x25519.str());
        x_pk.erase(it->second.pubkey_x25519);
    }
    if (it->second.pubkey_ed25519)
        ed_pk.erase(it->second.pubkey_ed25519);
    contacts.erase(it);
    return true;
}

bool Contacts::erase(const crypto::legacy_pubkey& pk) {
    oxenmq::pubkey_set rem;
    std::unique_lock lock{mut};
    bool ret = _erase(pk, rem);
    _remove_omq_keys(rem);
    return ret;
}

void Contacts::_update_omq_keys(oxenmq::pubkey_set& add, oxenmq::pubkey_set& rem) {
    if (!add.empty() || !rem.empty())
        omq.update_active_sns(std::move(add), std::move(rem));
}
void Contacts::_remove_omq_keys(oxenmq::pubkey_set& rem) {
    if (!rem.empty())
        omq.update_active_sns({}, std::move(rem));
}

std::optional<contact> Contacts::find(const crypto::legacy_pubkey& pk) const {
    std::shared_lock lock{mut};
    if (auto it = contacts.find(pk); it != contacts.end())
        return it->second;
    return std::nullopt;
}

std::optional<contact> Contacts::find(const crypto::x25519_pubkey& xpk) const {
    std::shared_lock lock{mut};
    if (auto xit = x_pk.find(xpk); xit != x_pk.end())
        if (auto it = contacts.find(xit->second); it != contacts.end())
            return it->second;
    return std::nullopt;
}

std::optional<contact> Contacts::find(const crypto::ed25519_pubkey& edpk) const {
    std::shared_lock lock{mut};
    if (auto eit = ed_pk.find(edpk); eit != ed_pk.end())
        if (auto it = contacts.find(eit->second); it != contacts.end())
            return it->second;
    return std::nullopt;
}

std::optional<crypto::legacy_pubkey> Contacts::lookup(const crypto::x25519_pubkey& xpk) const {
    std::shared_lock lock{mut};
    if (auto it = x_pk.find(xpk); it != x_pk.end())
        return it->second;
    return std::nullopt;
}

std::optional<crypto::legacy_pubkey> Contacts::lookup(const crypto::ed25519_pubkey& edpk) const {
    std::shared_lock lock{mut};
    if (auto it = ed_pk.find(edpk); it != ed_pk.end())
        return it->second;
    return std::nullopt;
}

std::set<crypto::legacy_pubkey> Contacts::get_pubkeys() const {
    std::shared_lock lock{mut};
    auto keys = std::views::keys(contacts);
    return {keys.begin(), keys.end()};
}

int Contacts::size() const {
    std::shared_lock lock{mut};
    return contacts.size();
}

std::pair<int, int> Contacts::counts() const {
    std::shared_lock lock{mut};
    std::pair<int, int> result{0, 0};
    auto& [total, contactable] = result;
    for (auto& [pk, c] : contacts) {
        total++;
        if (c)
            contactable++;
    }
    return result;
}

}  // namespace oxenss::snode
