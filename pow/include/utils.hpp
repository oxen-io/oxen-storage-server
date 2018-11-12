#pragma once

#include <string>
#include <stdint.h>

namespace util {

    inline bool parseTTL(const std::string& ttlString, uint64_t& ttl)
    {
        int ttlInt;
        try {
            ttlInt = std::stoi(ttlString);
        } catch(...) {
            return false;
        }

        if (ttlInt < 0)
            return false;

        ttl = static_cast<uint64_t>(ttlInt);

        return true;
    }

}
