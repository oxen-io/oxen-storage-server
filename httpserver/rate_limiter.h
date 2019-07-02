#pragma once

#include <boost/circular_buffer.hpp>

#include <chrono>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <utility> // for std::pair

/// https://en.wikipedia.org/wiki/Token_bucket

class RateLimiter {
  public:
    // TODO: make those two constants command line parameters?
    constexpr static uint32_t BUCKET_SIZE = 600;
    constexpr static uint32_t TOKEN_RATE = 300;
    constexpr static uint32_t MAX_CLIENTS = 10000;

    bool should_rate_limit(const std::string& identifier,
                           std::chrono::steady_clock::time_point now);
    bool should_rate_limit(const std::string& identifier);
    bool should_rate_limit_client(const std::string& identifier);
    bool should_rate_limit_client(const std::string& identifier,
                                  std::chrono::steady_clock::time_point now);

  private:
    struct TokenBucket {
        uint32_t num_tokens;
        std::chrono::steady_clock::time_point last_time_point;
    };
    using buffer_pair_t = std::pair<std::string, TokenBucket>;

    boost::circular_buffer<buffer_pair_t> buckets_{128};

    std::unordered_map<std::string, TokenBucket> client_buckets_;

    void clean_client_buckets(std::chrono::steady_clock::time_point now);

    void fill_bucket(TokenBucket& bucket,
                     std::chrono::steady_clock::time_point now);
};
