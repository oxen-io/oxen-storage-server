#include "utils.hpp"

#include <chrono>
#include <cstring>

#ifndef _WIN32
extern "C" {
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
}
#endif

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
    // Minimum time to live of 10 seconds, maximum of 14 days
    return (ttlInt >= 10 * 1000 && ttlInt <= 14 * 24 * 60 * 60 * 1000);
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

std::optional<std::filesystem::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifndef WIN32
    char* home = getenv("HOME");
    if (!home || !strlen(home))
        if (const auto* pwd = getpwuid(getuid()))
            home = pwd->pw_dir;

    if (home && strlen(home))
        return std::filesystem::u8path(home);
#endif

    return std::nullopt;
}

} // namespace util
