#include "rate_limiter.h"

#include <boost/test/unit_test.hpp>

#include <chrono>

BOOST_AUTO_TEST_SUITE(request_rate_limiter)

BOOST_AUTO_TEST_CASE(it_ratelimits_only_with_empty_bucket) {
    RateLimiter rate_limiter;
    const std::string identifier = "mypubkey";
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now),
                          false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now), true);

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::milliseconds(1000 / RateLimiter::TOKEN_RATE);
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier, now + delta),
                      false);
}

BOOST_AUTO_TEST_CASE(it_fills_up_bucket_steadily) {
    RateLimiter rate_limiter;
    const std::string identifier = "mypubkey";
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta =
            std::chrono::milliseconds(i * 1000 / RateLimiter::TOKEN_RATE);
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit(identifier, now + delta), false);
    }
}

BOOST_AUTO_TEST_CASE(it_handle_multiple_identifiers) {
    RateLimiter rate_limiter;
    const std::string identifier1 = "mypubkey";
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier1, now),
                          false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit(identifier1, now), true);

    // other id
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit("otherpubkey", now),
                      false);
}

BOOST_AUTO_TEST_SUITE_END()
