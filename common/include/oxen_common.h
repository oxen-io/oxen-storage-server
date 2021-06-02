#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include <oxenmq/hex.h>

namespace oxen {

using namespace std::literals;

inline constexpr size_t MAINNET_USER_PUBKEY_SIZE = 66;
inline constexpr size_t TESTNET_USER_PUBKEY_SIZE = 64;

inline bool is_mainnet = true;

inline size_t get_user_pubkey_size() {
    /// TODO: eliminate the need to check condition every time
    return is_mainnet ? MAINNET_USER_PUBKEY_SIZE : TESTNET_USER_PUBKEY_SIZE;
}

class user_pubkey_t {

    std::string pubkey_;

    explicit user_pubkey_t(std::string pk) : pubkey_(std::move(pk)) {}

  public:
    // Default constructor; constructs an invalid pubkey
    user_pubkey_t() = default;

    // bool conversion: returns true if this object contains a valid pubkey
    explicit operator bool() const { return !pubkey_.empty(); }

    // Replaces the stored pubkey with one parsed from the string `pk`.  If `pk` is not a valid
    // pubkey then `this` is put into an invalid-pubkey state (i.e. `(bool)pk` will be false).
    // Returns a reference to *this.
    user_pubkey_t& load(std::string pk);

    // Returns a reference to the user pubkey hex string, including mainnet prefix if on mainnet.
    // Returns an empty string for an invalid (default constructed) pubkey.
    const std::string& str() const { return pubkey_; }

    // Returns the un-prefixed pubkey hex string, or empty string for an invalid (default
    // constructed) pubkey.
    std::string_view key() const;
};

/// message received from a client
struct message_t {
    std::string pub_key;
    std::string data;
    std::string hash;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry;
};

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;

} // namespace oxen
