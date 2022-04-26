#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>

namespace oxen {

using namespace std::literals;

// Network byte + Ed25519 pubkey, encoded in bytes or hex.  On testnet we allow the network byte
// to be missing (and treat it as an implicit 00).
inline constexpr size_t USER_PUBKEY_SIZE_BYTES = 33;
inline constexpr size_t USER_PUBKEY_SIZE_HEX = USER_PUBKEY_SIZE_BYTES * 2;

inline bool is_mainnet = true;

class user_pubkey_t {
    int network_ = -1;
    std::string pubkey_;

    user_pubkey_t(int network, std::string raw_pk) :
            network_{network}, pubkey_{std::move(raw_pk)} {}

    friend class DatabaseImpl;

  public:
    // Default constructor; constructs an invalid pubkey
    user_pubkey_t() = default;

    // bool conversion: returns true if this object contains a valid pubkey
    explicit operator bool() const { return !pubkey_.empty(); }

    bool operator==(const user_pubkey_t& other) const {
        return type() == other.type() && raw() == other.raw();
    }

    // Replaces the stored pubkey with one parsed from the string `pk`.  `pk` can be either raw
    // bytes (33 bytes of netid + pubkey), or hex (66 hex digits).  If `pk` is not a valid
    // pubkey then `this` is put into an invalid-pubkey state (i.e. `(bool)pk` will be false).
    // Returns a reference to *this (primary that `if (upk.load(pk)) { ... }` can be used to
    // load-and-test).
    user_pubkey_t& load(std::string_view pk);

    // Returns the network id (0-255) that is typically prefixed on the beginning of the pubkey
    // string; currently 5 is used for Session Ed25519 pubkey IDs on mainnet, 0 is used for
    // Session IDs on testnet.  Returns -1 if this object does not contain a valid pubkey.
    int type() const { return network_; }

    // Returns the user pubkey hex string, not including the network prefix.  Returns an empty
    // string for an invalid (default constructed) pubkey.
    std::string hex() const;

    // Returns the user pubkey hex string, including the network prefix (unless on testnet with
    // netid == 0, in which case there is no prefix).  Returns an empty string for an invalid
    // (default constructed) pubkey.
    std::string prefixed_hex() const;

    // Returns the raw bytes that make up the pubkey (not including the type/network prefix).
    const std::string& raw() const { return pubkey_; }

    // Returns the raw bytes that makes up the pubkey, including the type/network prefix byte.
    // Returns an empty string for an invalid (default constructed) pubkey.
    std::string prefixed_raw() const;
};

enum class namespace_id : int16_t {
    Default = 0,  // Ordinary Session messages
    Min = -32768,
    Max = 32767,
    SessionSync = 5,     // Session sync data for imports & multidevice syncing
    ClosedV2 = 3,        // Reserved for future Session closed group implementations
    LegacyClosed = -10,  // For storage of "old" closed group messages; allows unauthenticated retrieval
};

constexpr bool is_public_namespace(namespace_id ns) {
    return static_cast<std::underlying_type_t<namespace_id>>(ns) % 10 == 0;
}

constexpr auto to_int(namespace_id ns) {
    return static_cast<std::underlying_type_t<namespace_id>>(ns);
}

std::string to_string(namespace_id ns);

constexpr auto NAMESPACE_MIN = to_int(namespace_id::Min);
constexpr auto NAMESPACE_MAX = to_int(namespace_id::Max);

/// message received from a client
struct message {
    user_pubkey_t pubkey;
    std::string hash;
    namespace_id msg_namespace;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry;
    std::string data;

    message() = default;

    message(user_pubkey_t pubkey,
            std::string hash,
            namespace_id msg_ns,
            std::chrono::system_clock::time_point timestamp,
            std::chrono::system_clock::time_point expiry,
            std::string data) :
            pubkey{std::move(pubkey)},
            hash{std::move(hash)},
            msg_namespace{msg_ns},
            timestamp{timestamp},
            expiry{expiry},
            data{std::move(data)} {}

    message(std::string hash,
            namespace_id msg_ns,
            std::chrono::system_clock::time_point timestamp,
            std::chrono::system_clock::time_point expiry,
            std::string data) :
            hash{std::move(hash)},
            msg_namespace{msg_ns},
            timestamp{timestamp},
            expiry{expiry},
            data{std::move(data)} {}
};

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;

}  // namespace oxen

namespace std {
template <>
struct hash<oxen::user_pubkey_t> {
    size_t operator()(const oxen::user_pubkey_t& pk) const {
        return static_cast<size_t>(pk.type()) ^ hash<std::string>{}(pk.raw());
    }
};

}  // namespace std
