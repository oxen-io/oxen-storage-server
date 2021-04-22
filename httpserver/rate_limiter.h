#pragma once

#include <boost/circular_buffer.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility> // for std::pair

#include "oxend_key.h"

/// https://en.wikipedia.org/wiki/Token_bucket

namespace oxen {

class RateLimiter {
  public:
    // TODO: make those two constants command line parameters?
    inline constexpr static uint32_t BUCKET_SIZE = 600;

    // Tokens (requests) per second
    inline constexpr static uint32_t TOKEN_RATE = 300; // Too much for a client??
    inline constexpr static uint32_t TOKEN_RATE_SN = 600;
    inline constexpr static uint32_t MAX_CLIENTS = 10000;

    bool should_rate_limit(
            const legacy_pubkey& pubkey,
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool should_rate_limit_client(
            uint32_t ip,
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

  private:
    struct TokenBucket {
        uint32_t num_tokens;
        std::chrono::steady_clock::time_point last_time_point;
    };

    boost::circular_buffer<std::pair<legacy_pubkey, TokenBucket>> buckets_{128};

    std::unordered_map<uint32_t, TokenBucket> client_buckets_;

    void clean_client_buckets(std::chrono::steady_clock::time_point now);

    // Add tokens based on the amount of time elapsed
    void fill_bucket(TokenBucket& bucket,
                     std::chrono::steady_clock::time_point now,
                     bool service_node = false);
};

}
