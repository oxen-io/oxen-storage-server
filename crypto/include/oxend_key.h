#pragma once

#include <array>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace oxen {

using namespace std::literals;

namespace detail {

template <size_t Length>
inline constexpr std::array<unsigned char, Length> null_bytes = {0};

void load_from_hex(void* buffer, size_t length, std::string_view hex);
void load_from_bytes(void* buffer, size_t length, std::string_view bytes);
std::string to_hex(const unsigned char* buffer, size_t length);

} // namespace detail

template <typename Derived, size_t KeyLength>
struct alignas(size_t) key_base : std::array<unsigned char, KeyLength> {
    std::string_view view() const { return {reinterpret_cast<const char*>(this->data()), KeyLength}; }
    std::string hex() const { return detail::to_hex(this->data(), KeyLength); }
    explicit operator bool() const { return *this != detail::null_bytes<KeyLength>; }

    // Loads the key from a hex string; throws if the hex is the wrong size or not hex.
    static Derived from_hex(std::string_view hex) {
        Derived d;
        detail::load_from_hex(d.data(), d.size(), hex);
        return d;
    }
    // Same as above, but returns nullopt if invalid instead of throwing
    static std::optional<Derived> maybe_from_hex(std::string_view hex) {
        try { return from_hex(hex); }
        catch (...) {}
        return std::nullopt;
    }
    // Loads the key from a byte string; throws if the wrong size.
    static Derived from_bytes(std::string_view bytes) {
        Derived d;
        detail::load_from_bytes(d.data(), d.size(), bytes);
        return d;
    }
};

template <typename Derived, size_t KeyLength>
struct pubkey_base : key_base<Derived, KeyLength> {
    using PubKeyBase = pubkey_base<Derived, KeyLength>;
};

struct legacy_pubkey : pubkey_base<legacy_pubkey, 32> {};
struct x25519_pubkey : pubkey_base<x25519_pubkey, 32> {};
struct ed25519_pubkey : pubkey_base<ed25519_pubkey, 32> {
    // Returns the {base32z}.snode representation of this pubkey
    std::string snode_address() const;
};

// Converts pubkey to a hex string when outputting.
inline std::ostream& operator<<(std::ostream& o, const legacy_pubkey& pk) { return o << pk.hex(); }
inline std::ostream& operator<<(std::ostream& o, const x25519_pubkey& pk) { return o << pk.hex(); }
inline std::ostream& operator<<(std::ostream& o, const ed25519_pubkey& pk) { return o << pk.hex(); }

template <typename Derived, size_t KeyLength>
struct seckey_base : key_base<Derived, KeyLength> {};

struct legacy_seckey : seckey_base<legacy_seckey, 32> {
    legacy_pubkey pubkey() const;
};
struct ed25519_seckey : seckey_base<ed25519_seckey, 64> {
    ed25519_pubkey pubkey() const;
};
struct x25519_seckey : seckey_base<x25519_seckey, 32> {
    x25519_pubkey pubkey() const;
};

using legacy_keypair = std::pair<legacy_pubkey, legacy_seckey>;
using ed25519_keypair = std::pair<ed25519_pubkey, ed25519_seckey>;
using x25519_keypair = std::pair<x25519_pubkey, x25519_seckey>;

} // namespace oxen

namespace std {

template <typename Derived, size_t N>
struct hash<oxen::pubkey_base<Derived, N>> {
    size_t operator()(const oxen::pubkey_base<Derived, N>& pk) const {
        // pubkeys are already random enough to use the first bytes directly as a good (and fast) hash value
        static_assert(alignof(decltype(pk)) >= alignof(size_t));
        return *reinterpret_cast<const size_t*>(pk.data());
    }
};

template <> struct hash<oxen::legacy_pubkey> : hash<oxen::legacy_pubkey::PubKeyBase> {};
template <> struct hash<oxen::x25519_pubkey> : hash<oxen::x25519_pubkey::PubKeyBase> {};
template <> struct hash<oxen::ed25519_pubkey> : hash<oxen::ed25519_pubkey::PubKeyBase> {};

}
