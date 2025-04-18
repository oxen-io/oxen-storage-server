#pragma once

#include <oxenmq/auth.h>
#include <iterator>
#include <set>
#include <shared_mutex>
#include <mutex>
#include <unordered_map>

#include <oxen/quic/ip.hpp>
#include <oxenmq/auth.h>
#include <oxenss/common/pubkey.h>
#include <oxenss/crypto/keys.h>

namespace oxenmq {
class OxenMQ;
}

namespace oxenss::snode {

using oxen::quic::ipv4;

// Contact information for a remote service node.
struct contact {
    ipv4 ip{};
    uint16_t https_port{0};
    uint16_t omq_quic_port{0};  // Same port number for both: quic is UDP, OMQ is TCP
    std::array<uint16_t, 3> version{0, 0, 0};
    crypto::ed25519_pubkey pubkey_ed25519{};
    crypto::x25519_pubkey pubkey_x25519{};

    // Returns true if this record is contactable: that is, has non-zero IP, ports, and X pubkey.
    bool contactable() const {
        return ip.addr != 0 && https_port != 0 && omq_quic_port != 0 && pubkey_x25519;
    }
    // Same as `.contactable()`
    explicit operator bool() const { return contactable(); }
};

template <typename It>
concept contact_pair_iterator = std::input_iterator<It> && requires(It it) {
    { std::get<0>(*it) } -> std::convertible_to<crypto::legacy_pubkey>;
    { std::get<1>(*it) } -> std::convertible_to<contact>;
};

// Container for holding contact info for all remote service nodes.
class Contacts {
    mutable std::shared_mutex mut;
    std::unordered_map<crypto::legacy_pubkey, contact> contacts;
    std::unordered_map<crypto::x25519_pubkey, crypto::legacy_pubkey> x_pk;
    std::unordered_map<crypto::ed25519_pubkey, crypto::legacy_pubkey> ed_pk;

    // Needed to update oxenmq of x25519 pubkey changes
    oxenmq::OxenMQ& omq;

    bool _update(
            const crypto::legacy_pubkey& pk,
            const contact& c,
            oxenmq::pubkey_set& omq_add,
            oxenmq::pubkey_set& omq_rem);
    bool _erase(const crypto::legacy_pubkey& pk, oxenmq::pubkey_set& omq_rem);
    void _update_omq_keys(oxenmq::pubkey_set& add, oxenmq::pubkey_set& rem);
    void _remove_omq_keys(oxenmq::pubkey_set& rem);

  public:
    explicit Contacts(oxenmq::OxenMQ& omq) : omq{omq} {}

    // SharedLockable support.  This is publicly exposed for more efficient access to methods ending
    // in _locked.
    void lock_shared() const { return mut.lock_shared(); }
    bool try_lock_shared() const { return mut.try_lock_shared(); }
    void unlock_shared() const { return mut.unlock_shared(); }

    // Looks up a contact; returns nullopt if the pubkey was not found.  Returns an
    // evaluates-as-false contact if the pubkey *was* found, but we have not yet received enough
    // information to contact it.
    std::optional<contact> find(const crypto::legacy_pubkey& pk) const;

    // Looks up a pubkey and returns a pointer to the contact record, or nullptr if not found.  The
    // caller must already hold a shared lock on this Contacts object to call this, and the pointer
    // is only valid while that lock remains held.
    const contact* find_locked(const crypto::legacy_pubkey& pk) const {
        if (auto it = contacts.find(pk); it != contacts.end())
            return &it->second;
        return nullptr;
    }

    // Looks up a contact by its x25519 pubkey; returns nullopt if the x25519 pubkey was not found.
    // Returns an evaluates-as-false contact if the pubkey was found, but valid ip/ports are not yet
    // known.
    std::optional<contact> find(const crypto::x25519_pubkey& xpk) const;

    // Looks up a contact by its ed25519 pubkey; returns nullopt if the ed25519 pubkey was not
    // found. Returns an evaluates-as-false contact if the pubkey was found, but valid ip/ports are
    // not yet known.
    std::optional<contact> find(const crypto::ed25519_pubkey& edpk) const;

    // Look up the primary pubkey given an X pubkey.  Returns nullopt if the given key is not known.
    std::optional<crypto::legacy_pubkey> lookup(const crypto::x25519_pubkey& xpk) const;

    // Look up the primary pubkey given an Ed pubkey.  Returns nullopt if the given key is not
    // known.
    std::optional<crypto::legacy_pubkey> lookup(const crypto::ed25519_pubkey& edpk) const;

    // Update a contact with new contact info.  The contact is inserted if it does not already
    // exist.  Existing contact info is updated, if changed, but will be preserved if the incoming
    // record has missing info (port, ip, pubkey) that is not missing from the existing record.
    //
    // Returns true if the update actually changed anything (new or updated record), false
    // otherwise.
    bool update(const crypto::legacy_pubkey& pk, const contact& c);

    // Returns the number of contact entries, whether or not they are contactable.
    int size() const;

    // Counts the number of contactable contacts.  Returns a pair of counts: the first value is the
    // total (same as .size()), and the second is the number that have contactable contact details.
    std::pair<int, int> counts() const;

    // Effectively the same as calling update(...) using the first and second element of each pair
    // element of [it, end), but more efficient as it does all updates in single lock.
    //
    // Returns the number of update() calls that return true.
    template <contact_pair_iterator It, std::sentinel_for<It> End>
    int update(It it, End end) {
        oxenmq::pubkey_set add, rem;
        int count = 0;
        {
            std::unique_lock lock{mut};
            for (; it != end; ++it)
                if (_update(std::get<0>(*it), std::get<1>(*it), add, rem))
                    count++;
        }
        _update_omq_keys(add, rem);
        return count;
    }

    // Erases a contact.  Returns true if the contact was found and erased, false otherwise.
    bool erase(const crypto::legacy_pubkey& pk);

    // Erases many contacts at once.  Equivalent to calling erase() multiple times, but more
    // efficient as it does it with a single lock.  Returns the number of erase() calls that
    // returned true.
    template <std::input_iterator It, std::sentinel_for<It> End>
    int erase(It it, End end) {
        oxenmq::pubkey_set rem;
        int count = 0;
        {
            std::unique_lock lock{mut};
            while (it != end)
                if (_erase(*it++, rem))
                    count++;
        }
        _remove_omq_keys(rem);
        return count;
    }

    // Does an update(it1, end1) and erase(it2, end2) atomically.
    template <
            contact_pair_iterator It1,
            std::sentinel_for<It1> End1,
            std::input_iterator It2,
            std::sentinel_for<It2> End2>
    int update_and_erase(It1 it1, End1 end1, It2 it2, End2 end2) {
        oxenmq::pubkey_set add, rem;
        int count = 0;
        {
            std::unique_lock lock{mut};
            for (; it1 != end1; ++it1)
                if (_update(std::get<0>(*it1), std::get<1>(*it1), add, rem))
                    count++;
            while (it2 != end2)
                if (_erase(*it2++, rem))
                    count++;
        }
        _update_omq_keys(add, rem);
        return count;
    }

    // Copies all known primary pubkeys into the given iterator.
    template <std::output_iterator<crypto::legacy_pubkey> It>
    void copy_pubkeys(It out) const {
        std::shared_lock lock{mut};
        for (auto& [k, _v] : contacts)
            *out++ = k;
    }

    // Returns set of all primary pubkeys.
    std::set<crypto::legacy_pubkey> get_pubkeys() const;

    // Copies all known X25519 pubkeys into the given iterator.
    template <std::output_iterator<crypto::legacy_pubkey> It>
    void copy_x_pubkeys(It out) const {
        std::shared_lock lock{mut};
        for (auto& [k, _v] : x_pk)
            *out++ = k;
    }

    // Same as above, but output the binary pubkeys as 32-byte std::strings
    template <std::output_iterator<std::string> It>
    void copy_x_pubkeys(It out) const {
        std::shared_lock lock{mut};
        for (auto& [k, _v] : x_pk)
            *out++ = k.to_string();
    }
};

}  // namespace oxenss::snode
