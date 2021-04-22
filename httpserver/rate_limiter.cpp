#include "rate_limiter.h"

#include "oxen_common.h"
#include "oxen_logger.h"

#include <algorithm>

namespace oxen {

namespace {

// Time between to consecutive tokens for clients
constexpr std::chrono::microseconds TOKEN_PERIOD_US =
    1'000'000us / RateLimiter::TOKEN_RATE;

// Time between to consecutive tokens for snodes
constexpr std::chrono::microseconds TOKEN_PERIOD_SN_US =
    1'000'000us / RateLimiter::TOKEN_RATE_SN;

constexpr std::chrono::microseconds FILL_EMPTY_BUCKET_US =
    TOKEN_PERIOD_US * RateLimiter::BUCKET_SIZE;

}

void RateLimiter::fill_bucket(TokenBucket& bucket,
                              std::chrono::steady_clock::time_point now,
                              bool service_node) {
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        now - bucket.last_time_point);
    // clamp elapsed time to how long it takes to fill up the whole bucket
    // (simplifies overlow checking)
    elapsed_us = std::min(elapsed_us, FILL_EMPTY_BUCKET_US);

    const auto token_period =
        service_node ? TOKEN_PERIOD_SN_US : TOKEN_PERIOD_US;

    const uint32_t token_added = elapsed_us.count() / token_period.count();
    // clamp tokens to bucket size
    bucket.num_tokens = std::min(BUCKET_SIZE, bucket.num_tokens + token_added);
}

bool RateLimiter::should_rate_limit(const legacy_pubkey& pubkey,
                                    std::chrono::steady_clock::time_point now) {
    const auto it = std::find_if(
        buckets_.begin(), buckets_.end(),
        [&](const auto& pair) { return pair.first == pubkey; });
    if (it != buckets_.end()) {
        auto& bucket = it->second;

        fill_bucket(bucket, now);

        if (bucket.num_tokens == 0) {
            return true;
        }

        bucket.num_tokens--;
        bucket.last_time_point = now;
    } else {
        buckets_.push_back({pubkey, TokenBucket{BUCKET_SIZE-1, now}});
    }

    return false;
}

bool RateLimiter::should_rate_limit_client(
        uint32_t ip, std::chrono::steady_clock::time_point now) {

    const auto it = client_buckets_.find(ip);
    if (it != client_buckets_.end()) {
        auto& bucket = it->second;

        fill_bucket(bucket, now);

        if (bucket.num_tokens == 0) {
            return true;
        }

        bucket.num_tokens--;
        bucket.last_time_point = now;
    } else {
        if (client_buckets_.size() >= MAX_CLIENTS) {
            clean_client_buckets(now);
        }
        if (client_buckets_.size() >= MAX_CLIENTS) {
            return true;
        }
        client_buckets_.emplace(ip, TokenBucket{BUCKET_SIZE-1, now});
    }

    return false;
}

void RateLimiter::clean_client_buckets(
    std::chrono::steady_clock::time_point now) {

    auto it = client_buckets_.begin();

    while (it != client_buckets_.end()) {
        auto& bucket = it->second;
        fill_bucket(bucket, now);
        if (bucket.num_tokens == BUCKET_SIZE) {
            it = client_buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

}
