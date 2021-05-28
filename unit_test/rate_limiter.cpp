#include "rate_limiter.h"
#include "oxend_key.h"

#include <catch2/catch.hpp>
#include <oxenmq/oxenmq.h>

#include <chrono>

using oxen::RateLimiter;
using namespace std::literals;

TEST_CASE("rate limiter - snode - empty bucket", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now));
    }
    CHECK(rate_limiter.should_rate_limit(identifier, now));

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now + delta));
}

TEST_CASE("rate limiter - snode - steady bucket fillup", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul /
                                                     RateLimiter::TOKEN_RATE);
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now + delta));
    }
}

TEST_CASE("rate limiter - snode - multiple identifiers", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier1 = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier1, now));
    }
    CHECK(rate_limiter.should_rate_limit(identifier1, now));

    auto identifier2 = oxen::legacy_pubkey::from_hex(
            "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    // other id
    CHECK_FALSE(rate_limiter.should_rate_limit(identifier2, now));
}

TEST_CASE("rate limiter - client - empty bucket", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier, now));
    }
    CHECK(rate_limiter.should_rate_limit_client(identifier, now));

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    CHECK_FALSE(
        rate_limiter.should_rate_limit_client(identifier, now + delta));
}

TEST_CASE("rate limiter - client - steady bucket fillup", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul /
                                                     RateLimiter::TOKEN_RATE);
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier, now + delta));
    }
}

TEST_CASE("rate limiter - client - multiple identifiers", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier1 = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier1, now));
    }
    CHECK(rate_limiter.should_rate_limit_client(identifier1, now));

    uint32_t identifier2 = (10<<24) + (1<<16) + (1<<8) + 10;
    // other id
    CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier2, now));
}

TEST_CASE("rate limiter - client - max client limit", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    const auto now = std::chrono::steady_clock::now();

    uint32_t ip_start = (10<<24) + 1;

    for (uint32_t i = 0; i < RateLimiter::MAX_CLIENTS; ++i) {
        rate_limiter.should_rate_limit_client(ip_start + i, now);
    }
    uint32_t overflow_ip = ip_start + RateLimiter::MAX_CLIENTS;
    CHECK(rate_limiter.should_rate_limit_client(overflow_ip, now));
    // Wait for buckets to be filled
    const auto delta = 1'000'000us / RateLimiter::TOKEN_RATE;
    CHECK_FALSE(rate_limiter.should_rate_limit_client(overflow_ip, now + delta));
}
