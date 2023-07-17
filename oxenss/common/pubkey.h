#pragma once

#include <string>

namespace oxen {

// Network byte + Ed25519 pubkey, encoded in bytes or hex.  On testnet we allow the network byte
// to be missing (and treat it as an implicit 00).
inline constexpr size_t USER_PUBKEY_SIZE_BYTES = 33;
inline constexpr size_t USER_PUBKEY_SIZE_HEX = USER_PUBKEY_SIZE_BYTES * 2;

class user_pubkey {
    int network_ = -1;
    std::string pubkey_;

    user_pubkey(int network, std::string raw_pk) :
            network_{network}, pubkey_{std::move(raw_pk)} {}

    friend class DatabaseImpl;

  public:
    // Default constructor; constructs an invalid pubkey
    user_pubkey() = default;

    // bool conversion: returns true if this object contains a valid pubkey
    explicit operator bool() const { return !pubkey_.empty(); }

    bool operator==(const user_pubkey& other) const {
        return type() == other.type() && raw() == other.raw();
    }

    // Replaces the stored pubkey with one parsed from the string `pk`.  `pk` can be either raw
    // bytes (33 bytes of netid + pubkey), or hex (66 hex digits).  If `pk` is not a valid
    // pubkey then `this` is put into an invalid-pubkey state (i.e. `(bool)pk` will be false).
    // Returns a reference to *this (primary that `if (upk.load(pk)) { ... }` can be used to
    // load-and-test).
    user_pubkey& load(std::string_view pk);

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

}  // namespace oxen

namespace std {
template <>
struct hash<oxen::user_pubkey> {
    size_t operator()(const oxen::user_pubkey& pk) const {
        return static_cast<size_t>(pk.type()) ^ hash<std::string>{}(pk.raw());
    }
};
}  // namespace std
