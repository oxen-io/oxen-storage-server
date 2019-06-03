#include "rate_limiter.h"

#include <algorithm>

constexpr uint32_t RateLimiter::BUCKET_SIZE;
constexpr uint32_t RateLimiter::TOKEN_RATE;

using namespace std::chrono_literals;

constexpr static std::chrono::microseconds TOKEN_PERIOD_US =
    std::chrono::duration_cast<std::chrono::microseconds>(1s) /
    RateLimiter::TOKEN_RATE;
constexpr static std::chrono::microseconds FILL_EMPTY_BUCKET_US =
    TOKEN_PERIOD_US * RateLimiter::BUCKET_SIZE;

void RateLimiter::fill_bucket(TokenBucket& bucket,
                              std::chrono::steady_clock::time_point now) {
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        now - bucket.last_time_point);
    // clamp elapsed time to how long it takes to fill up the whole bucket
    // (simplifies overlow checking)
    elapsed_us = std::min(elapsed_us, FILL_EMPTY_BUCKET_US);
    const uint32_t token_added = elapsed_us.count() / TOKEN_PERIOD_US.count();
    // clamp tokens to bucket size
    bucket.num_tokens = std::min(BUCKET_SIZE, bucket.num_tokens + token_added);
}

bool RateLimiter::should_rate_limit(const std::string& identifier) {
    return should_rate_limit(identifier, std::chrono::steady_clock::now());
}

bool RateLimiter::should_rate_limit(const std::string& identifier,
                                    std::chrono::steady_clock::time_point now) {
    const auto it = std::find_if(
        buckets_.begin(), buckets_.end(),
        [&](const buffer_pair_t& pair) { return pair.first == identifier; });
    if (it != buckets_.end()) {
        auto& bucket = it->second;

        fill_bucket(bucket, now);

        if (bucket.num_tokens == 0) {
            return true;
        }

        bucket.num_tokens--;
        bucket.last_time_point = now;
    } else {
        const TokenBucket bucket{BUCKET_SIZE - 1, now};
        buckets_.push_back(std::make_pair(identifier, bucket));
    }

    return false;
}
