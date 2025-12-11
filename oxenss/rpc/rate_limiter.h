#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <oxen/quic/ip.hpp>
#include <unordered_map>

#include <oxenss/crypto/keys.h>

namespace oxenmq {
class OxenMQ;
}

/// https://en.wikipedia.org/wiki/Token_bucket

namespace oxenss::rpc {

// TODO: make oxen::quic::ipv6 should be std::hash-able
struct addr_hash {
    static inline constexpr size_t inverse_golden_ratio =
            sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;
    size_t operator()(const oxen::quic::ipv6& addr) const noexcept {
        auto h = std::hash<uint64_t>{}(addr.hi);
        h ^= std::hash<uint64_t>{}(addr.lo) + inverse_golden_ratio + (h << 6) + (h >> 2);
        return h;
    }
};

class RateLimiter {
  public:
    // TODO: make those two constants command line parameters?
    inline constexpr static uint32_t BUCKET_SIZE = 600;

    // Tokens (requests) per second
    inline constexpr static uint32_t TOKEN_RATE = 300;  // Too much for a client??
    inline constexpr static uint32_t TOKEN_RATE_SN = 600;
    inline constexpr static uint32_t MAX_CLIENTS = 10000;

    RateLimiter() = delete;
    RateLimiter(oxenmq::OxenMQ& omq);

    bool should_rate_limit(
            const crypto::legacy_pubkey& pubkey,
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool should_rate_limit_client(
            const oxen::quic::ipv6& ip,
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  private:
    struct TokenBucket {
        uint32_t num_tokens;
        std::chrono::steady_clock::time_point last_time_point;
    };

    std::mutex mutex_;

    std::unordered_map<crypto::legacy_pubkey, TokenBucket> snode_buckets_;
    std::unordered_map<oxen::quic::ipv6, TokenBucket, addr_hash> client_buckets_;

    void clean_buckets(std::chrono::steady_clock::time_point now);
};

}  // namespace oxenss::rpc
