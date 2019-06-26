#include "rate_limiter.h"

#include <boost/chrono.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread/thread.hpp>

#include <chrono>

BOOST_AUTO_TEST_SUITE(snode_request_rate_limiter)

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

BOOST_AUTO_TEST_SUITE(client_request_rate_limiter)

BOOST_AUTO_TEST_CASE(it_ratelimits_only_with_empty_bucket) {
    RateLimiter rate_limiter;
    const std::string identifier = "myipaddress";
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier, now), false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(identifier, now),
                      true);

    // wait just enough to allow one more request
    const auto delta =
        std::chrono::milliseconds(1000 / RateLimiter::TOKEN_RATE);
    BOOST_CHECK_EQUAL(
        rate_limiter.should_rate_limit_client(identifier, now + delta), false);
}

BOOST_AUTO_TEST_CASE(it_fills_up_bucket_steadily) {
    RateLimiter rate_limiter;
    const std::string identifier = "myipaddress";
    const auto now = std::chrono::steady_clock::now();
    // make requests at the same rate as the bucket is filling up
    for (int i = 0; i < RateLimiter::BUCKET_SIZE * 10; ++i) {
        const auto delta =
            std::chrono::milliseconds(i * 1000 / RateLimiter::TOKEN_RATE);
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier, now + delta),
            false);
    }
}

BOOST_AUTO_TEST_CASE(it_handles_multiple_identifiers) {
    RateLimiter rate_limiter;
    const std::string identifier1 = "myipaddress";
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::BUCKET_SIZE; ++i) {
        BOOST_CHECK_EQUAL(
            rate_limiter.should_rate_limit_client(identifier1, now), false);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(identifier1, now),
                      true);

    // other id
    BOOST_CHECK_EQUAL(
        rate_limiter.should_rate_limit_client("otheripaddress", now), false);
}

BOOST_AUTO_TEST_CASE(it_limits_too_many_unique_clients) {
    RateLimiter rate_limiter;
    const auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < RateLimiter::MAX_CLIENTS; ++i) {
        rate_limiter.should_rate_limit_client(std::to_string(i), now);
    }
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(
                          std::to_string(RateLimiter::MAX_CLIENTS + 1), now),
                      true);
    // Wait for buckets to be filled
    boost::this_thread::sleep_for(
        boost::chrono::milliseconds(1000 / RateLimiter::TOKEN_RATE));
    BOOST_CHECK_EQUAL(rate_limiter.should_rate_limit_client(
                          std::to_string(RateLimiter::MAX_CLIENTS + 1), now),
                      false);
}

BOOST_AUTO_TEST_SUITE_END()
