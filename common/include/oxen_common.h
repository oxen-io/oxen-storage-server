#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <ostream>
#include <string>
#include <string_view>

#include <oxenmq/hex.h>

namespace oxen {

using namespace std::literals;

using time_point_t = std::chrono::steady_clock::time_point;

inline constexpr size_t MAINNET_USER_PUBKEY_SIZE = 66;
inline constexpr size_t TESTNET_USER_PUBKEY_SIZE = 64;

inline bool is_mainnet = true;

inline size_t get_user_pubkey_size() {
    /// TODO: eliminate the need to check condition every time
    return is_mainnet ? MAINNET_USER_PUBKEY_SIZE : TESTNET_USER_PUBKEY_SIZE;
}

class user_pubkey_t {

    std::string pubkey_;

    user_pubkey_t() {}

    user_pubkey_t(std::string pk) : pubkey_(std::move(pk)) {}

  public:
    static user_pubkey_t create(std::string pk, bool& success) {
        success = true;
        if (pk.size() != get_user_pubkey_size()) {
            success = false;
            return {};
        }
        return user_pubkey_t(std::move(pk));
    }

    const std::string& str() const { return pubkey_; }
};

/// message as received by client
struct message_t {

    std::string pub_key;
    std::string data;
    std::string hash;
    uint64_t ttl;
    uint64_t timestamp;
    /// Nonce is now meaningless, but we keep it to avoid breaking the protocol
    std::string nonce;

    message_t(const std::string& pk, const std::string& text,
              const std::string& hash, uint64_t ttl, uint64_t timestamp)
        : pub_key(pk), data(text), hash(hash), ttl(ttl), timestamp(timestamp) {}
};

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;

} // namespace oxen
