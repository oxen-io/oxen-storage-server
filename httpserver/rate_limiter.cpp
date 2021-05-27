#include "rate_limiter.h"

#include "oxen_common.h"

#include <chrono>
#include <oxenmq/oxenmq.h>

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

RateLimiter::RateLimiter(oxenmq::OxenMQ& omq) {
    omq.add_timer([this] {
        std::lock_guard lock{mutex_};
        clean_buckets(std::chrono::steady_clock::now());
    }, 10s);
}

template <typename TokenBucket>
static bool fill_bucket(
        TokenBucket& bucket,
        std::chrono::steady_clock::time_point now,
        bool service_node = false) {
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
        now - bucket.last_time_point);
    // clamp elapsed time to how long it takes to fill up the whole bucket
    // (simplifies overlow checking)
    elapsed_us = std::min(elapsed_us, FILL_EMPTY_BUCKET_US);

    const auto token_period =
        service_node ? TOKEN_PERIOD_SN_US : TOKEN_PERIOD_US;

    const uint32_t token_added = elapsed_us.count() / token_period.count();
    bucket.num_tokens += token_added;
    if (bucket.num_tokens >= RateLimiter::BUCKET_SIZE) {
        bucket.num_tokens = RateLimiter::BUCKET_SIZE;
        return true;
    }
    return false;
}

template <typename TokenBucket>
static bool remove_token(TokenBucket& b, std::chrono::steady_clock::time_point now, bool sn = false) {
    fill_bucket(b, now, sn);
    if (b.num_tokens == 0)
        return false;
    b.num_tokens--;
    b.last_time_point = now;
    return true;
}

bool RateLimiter::should_rate_limit(const legacy_pubkey& pubkey,
                                    std::chrono::steady_clock::time_point now) {
    std::lock_guard lock{mutex_};
    if (auto [it, ins] = snode_buckets_.emplace(pubkey, TokenBucket{BUCKET_SIZE-1, now});
            ins)
        return false;
    else
        return !remove_token(it->second, now, true);
}

bool RateLimiter::should_rate_limit_client(
        uint32_t ip, std::chrono::steady_clock::time_point now) {
    std::lock_guard lock{mutex_};

    if (auto it = client_buckets_.find(ip); it != client_buckets_.end())
        return !remove_token(it->second, now);

    if (client_buckets_.size() >= MAX_CLIENTS) {
        clean_buckets(now);
        if (client_buckets_.size() >= MAX_CLIENTS)
            return true;
    }
    client_buckets_.emplace(ip, TokenBucket{BUCKET_SIZE-1, now});
    return false;
}

void RateLimiter::clean_buckets(
    std::chrono::steady_clock::time_point now) {

    for (auto it = client_buckets_.begin(); it != client_buckets_.end(); ) {
        if (fill_bucket(it->second, now))
            it = client_buckets_.erase(it);
        else
            ++it;
    }

    for (auto it = snode_buckets_.begin(); it != snode_buckets_.end(); ) {
        if (fill_bucket(it->second, now, true))
            it = snode_buckets_.erase(it);
        else
            ++it;
    }
}

}
