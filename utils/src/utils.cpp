#include "utils.hpp"

#include <chrono>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <lokimq/base64.h>
#include <lokimq/base32z.h>
#include <lokimq/hex.h>

namespace util {

uint64_t get_time_ms() {
    const auto timestamp = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               timestamp.time_since_epoch())
        .count();
}

bool validateTimestamp(uint64_t timestamp, uint64_t ttl) {
    const uint64_t cur_time = get_time_ms();
    // Timestamp must not be in the future (with some tolerance)
    if (timestamp > cur_time + 10000)
        return false;

    // Don't need to worry about overflow for several hundred million years
    const uint64_t exp_time = timestamp + ttl;

    // Don't accept timestamp that has already expired
    if (exp_time < cur_time)
        return false;

    return true;
}

bool parseTimestamp(const std::string& timestampString, const uint64_t ttl,
                    uint64_t& timestamp) {
    try {
        timestamp = std::stoull(timestampString);
    } catch (...) {
        return false;
    }

    return validateTimestamp(timestamp, ttl);
}

bool validateTTL(uint64_t ttlInt) {
    // Minimum time to live of 10 seconds, maximum of 4 days
    return (ttlInt >= 10 * 1000 && ttlInt <= 96 * 60 * 60 * 1000);
}

bool parseTTL(const std::string& ttlString, uint64_t& ttl) {
    int ttlInt;
    try {
        ttlInt = std::stoi(ttlString);
    } catch (...) {
        return false;
    }

    if (!validateTTL(ttlInt))
        return false;

    ttl = static_cast<uint64_t>(ttlInt);

    return true;
}

std::mt19937_64& rng() {
    static thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

uint64_t uniform_distribution_portable(uint64_t n) {
    return uniform_distribution_portable(rng(), n);
}

uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n) {
    const uint64_t secure_max =
        mersenne_twister.max() - mersenne_twister.max() % n;
    uint64_t x;
    do
        x = mersenne_twister();
    while (x >= secure_max);
    return x / (secure_max / n);
}

int get_fd_limit() {

#ifdef _WIN32
    return -1;
#endif

    return sysconf(_SC_OPEN_MAX);
}

} // namespace util
