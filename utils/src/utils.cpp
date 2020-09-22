#include "utils.hpp"

#include <boost/beast/core/detail/base64.hpp>

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

// clang-format off
constexpr uint8_t hex_to_nibble(const char& ch) {
    return
        (ch >= '0' && ch <= '9') ? ch - '0' :
        (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10 :
        (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 :
        0;
}
// clang-format on

constexpr uint8_t hexpair_to_byte(const char& hi, const char& lo) {
    return hex_to_nibble(hi) << 4 | hex_to_nibble(lo);
}

std::string hex_to_bytes(const std::string& hex) {
    std::string result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0, end = hex.size() & ~1; i < end; i += 2)
        result.push_back(hexpair_to_byte(hex[i], hex[i + 1]));
    return result;
}

// TODO: stop relying on beast::detail
namespace base64 = boost::beast::detail::base64;

// base64 stuff was copied from boost 1.66 sources
std::string base64_decode(std::string const& data) {
    std::string dest;
    dest.resize(base64::decoded_size(data.size()));
    auto const result = base64::decode(&dest[0], data.data(), data.size());
    dest.resize(result.first);
    return dest;
}

static std::string base64_encode(std::uint8_t const* data, std::size_t len) {
    std::string dest;
    dest.resize(base64::encoded_size(len));
    dest.resize(base64::encode(&dest[0], data, len));
    return dest;
}

std::string base64_encode(std::string const& s) {
    return base64_encode(reinterpret_cast<std::uint8_t const*>(s.data()),
                         s.size());
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
