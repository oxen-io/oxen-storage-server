#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/crypto/keys.h>

#include <catch2/catch.hpp>
#include <oxenmq/oxenmq.h>

#include <chrono>

using oxenss::rpc::RateLimiter;
using namespace oxenss::crypto;
using namespace std::literals;

TEST_CASE("rate limiter - snode - empty bucket", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now));
    }
    CHECK(rate_limiter.should_rate_limit(identifier, now));

    // wait just enough to allow one more request
    const auto delta = std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now + delta));
}

TEST_CASE("rate limiter - snode - steady bucket fillup", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul / RateLimiter::TOKEN_RATE);
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier, now + delta));
    }
}

TEST_CASE("rate limiter - snode - multiple identifiers", "[ratelim][snode]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier1 = legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit(identifier1, now));
    }
    CHECK(rate_limiter.should_rate_limit(identifier1, now));

    auto identifier2 = legacy_pubkey::from_hex(
            "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    // other id
    CHECK_FALSE(rate_limiter.should_rate_limit(identifier2, now));
}

oxen::quic::ipv6 map_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return oxen::quic::ipv6{
            0,
            0,
            0,
            0,
            0,
            0xffff,
            static_cast<uint16_t>((a << 8) | b),
            static_cast<uint16_t>((c << 8) | d)};
}

TEST_CASE("rate limiter - client - empty bucket", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = map_ipv4(10, 1, 1, 13);
    const auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier, now));
    }
    CHECK(rate_limiter.should_rate_limit_client(identifier, now));

    // wait just enough to allow one more request
    const auto delta = std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier, now + delta));
}

TEST_CASE("rate limiter - client - steady bucket fillup", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = map_ipv4(10, 1, 1, 13);
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul / RateLimiter::TOKEN_RATE);
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier, now + delta));
    }
}

TEST_CASE("rate limiter - client - multiple identifiers", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier1 = map_ipv4(10, 1, 1, 13);
    const auto now = std::chrono::steady_clock::now();

    for (size_t i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier1, now));
    }
    CHECK(rate_limiter.should_rate_limit_client(identifier1, now));

    auto identifier2 = map_ipv4(10, 1, 1, 10);
    // other id
    CHECK_FALSE(rate_limiter.should_rate_limit_client(identifier2, now));
}

TEST_CASE("rate limiter - client - max client limit", "[ratelim][client]") {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    const auto now = std::chrono::steady_clock::now();

    auto ip = map_ipv4(10, 0, 0, 1);

    for (uint32_t i = 0; i < RateLimiter::MAX_CLIENTS; ++i) {
        ip = ip.next_ip().value();
        rate_limiter.should_rate_limit_client(ip, now);
    }
    ip = ip.next_ip().value();
    CHECK(rate_limiter.should_rate_limit_client(ip, now));
    // Wait for buckets to be filled
    const auto delta = 1'000'000us / RateLimiter::TOKEN_RATE;
    CHECK_FALSE(rate_limiter.should_rate_limit_client(ip, now + delta));
}
