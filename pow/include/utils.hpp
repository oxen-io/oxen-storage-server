#pragma once

#include <stdint.h>
#include <string>

namespace util {

inline bool parseTTL(const std::string& ttlString, uint64_t& ttl) {
    int ttlInt;
    try {
        ttlInt = std::stoi(ttlString);
    } catch (...) {
        return false;
    }

    // Maximum time to live of 4 days
    if (ttlInt < 0 || ttlInt > 96 * 60 * 60)
        return false;

    ttl = static_cast<uint64_t>(ttlInt);

    return true;
}

} // namespace util
