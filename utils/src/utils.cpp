#include "utils.hpp"

#include <chrono>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace util {

uint64_t get_time_ms() {
    const auto timestamp = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               timestamp.time_since_epoch())
        .count();
}

constexpr uint8_t hex_to_nibble(const char& ch) {
    return (ch >= '0' && ch <= '9')
               ? ch - 48
               : ((ch >= 'A' && ch <= 'F')
                      ? ch - 55
                      : ((ch >= 'a' && ch <= 'f') ? ch - 87 : 0));
}

constexpr uint8_t hexpair_to_byte(const char& hi, const char& lo) {
    return hex_to_nibble(hi) << 4 | hex_to_nibble(lo);
}

std::string hex_to_base32z(const std::string& src) {
    // decode to binary
    std::vector<uint8_t> bin;
    // odd sized is invalid
    if (src.size() & 1)
        return "";
    {
        auto itr = src.begin();
        while (itr != src.end()) {
            const char hi = *itr;
            ++itr;
            const char lo = *itr;
            ++itr;
            bin.emplace_back(hexpair_to_byte(hi, lo));
        }
    }
    // encode to base32z
    char buf[64] = {0};
    std::string result;
    if (char const* dest = base32z_encode(bin, buf))
        result = dest;

    return result;
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

uint64_t uniform_distribution_portable(uint64_t n) {

    static thread_local std::mt19937_64 generator;
    return uniform_distribution_portable(generator, n);
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
