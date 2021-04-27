#pragma once

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <random>
#include <string>

namespace util {

bool validateTTL(uint64_t ttlInt);
// Convert ttl string into uint64_t, return bool for success/fail
bool parseTTL(const std::string& ttlString, uint64_t& ttl);

bool validateTimestamp(uint64_t timestamp, uint64_t ttl);
// Convert timestamp string into uint64_t, return bool for success/fail
bool parseTimestamp(const std::string& timestampString, const uint64_t ttl,
                    uint64_t& timestamp);

// Get current time in milliseconds
uint64_t get_time_ms();

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n) using `rng()`
uint64_t uniform_distribution_portable(uint64_t n);

/// Returns a random number from [0, n); (copied from lokid)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n);

/// Return the open file limit (-1 on failure)
int get_fd_limit();

inline bool ends_with(std::string_view str, std::string_view suffix) {
    return str.size() >= suffix.size() &&
           str.substr(str.size() - suffix.size()) == suffix;
}

inline bool starts_with(std::string_view str, std::string_view prefix) {
  return str.substr(0, prefix.size()) == prefix;
}

/// Joins [begin, end) with a delimiter and returns the resulting string.  Elements can be anything
/// that can be sent to an ostream via `<<`.  The OSS template here is mainly to trick the compiler
/// (especially macos clang) into being happy with this include even when std::ostringstream isn't
/// yet available (and to put the include responsibility on the caller).
template <typename It, typename OSS = std::ostringstream>
std::string join(std::string_view delimiter, It begin, It end) {
    OSS o;
    if (begin != end)
        o << *begin++;
    while (begin != end)
        o << delimiter << *begin++;
    return o.str();
}

/// Wrapper around the above that takes a container and passes c.begin(), c.end() to the above.
template <typename Container>
std::string join(std::string_view delimiter, const Container& c) {
    return join(delimiter, c.begin(), c.end());
}

std::optional<std::filesystem::path> get_home_dir();

} // namespace util
