#include "rate_limiter.h"
#include "oxend_key.h"

#include <boost/test/unit_test.hpp>
#include <oxenmq/oxenmq.h>

#include <chrono>

using oxen::RateLimiter;
using namespace std::literals;

BOOST_AUTO_TEST_SUITE(snode_request_rate_limiter)

BOOST_AUTO_TEST_CASE(it_ratelimits_only_with_empty_bucket) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now),
                          false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now), true);

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now + delta),
                      false);
}

BOOST_AUTO_TEST_CASE(it_fills_up_bucket_steadily) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul /
                                                     RateLimiter::TOKEN_RATE);
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit(identifier, now + delta), false);
    }
}

BOOST_AUTO_TEST_CASE(it_handle_multiple_identifiers) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    auto identifier1 = oxen::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier1, now),
                          false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier1, now), true);

    auto identifier2 = oxen::legacy_pubkey::from_hex(
            "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abc000");
    // other id
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier2, now),
                      false);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(client_request_rate_limiter)

BOOST_AUTO_TEST_CASE(it_ratelimits_only_with_empty_bucket) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier, now), false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(identifier, now),
                      true);

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::microseconds(1'000'000ul / RateLimiter::TOKEN_RATE);
    BOOST_CHECK_EQUAL(
        rate_limiter.should_rate_limit_client(identifier, now + delta), false);
}

BOOST_AUTO_TEST_CASE(it_fills_up_bucket_steadily) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta = std::chrono::microseconds(i * 1'000'000ul /
                                                     RateLimiter::TOKEN_RATE);
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier, now + delta),
            false);
    }
}

BOOST_AUTO_TEST_CASE(it_handles_multiple_identifiers) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    uint32_t identifier1 = (10<<24) + (1<<16) + (1<<8) + 13;
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier1, now), false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(identifier1, now),
                      true);

    uint32_t identifier2 = (10<<24) + (1<<16) + (1<<8) + 10;
    // other id
    BOOST_CHECK_EQUAL(
        rate_limiter.should_rate_limit_client(identifier2, now), false);
}

BOOST_AUTO_TEST_CASE(it_limits_too_many_unique_clients) {
    oxenmq::OxenMQ omq;
    RateLimiter rate_limiter{omq};
    const auto now = std::chrono::steady_clock::now();

    uint32_t ip_start = (10<<24) + 1;

    for (uint32_t i = 0; i < RateLimiter::MAX_CLIENTS; ++i) {
        rate_limiter.should_rate_limit_client(ip_start + i, now);
    }
    uint32_t overflow_ip = ip_start + RateLimiter::MAX_CLIENTS;
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(
                          overflow_ip, now),
                      true);
    // Wait for buckets to be filled
    const auto delta = 1'000'000us / RateLimiter::TOKEN_RATE;
    BOOST_CHECK_EQUAL(
        rate_limiter.should_rate_limit_client(
            overflow_ip, now + delta),
        false);
}

BOOST_AUTO_TEST_SUITE_END()
