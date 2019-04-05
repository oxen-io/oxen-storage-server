#pragma once

#include <algorithm>
#include <stdint.h>
#include <string>
#include <vector>

namespace util {

bool parseTTL(const std::string& ttlString, uint64_t& ttl);

// adapted from Lokinet llarp/encode.hpp
// from  https://en.wikipedia.org/wiki/Base32#z-base-32
static const char zbase32_alpha[] = {'y', 'b', 'n', 'd', 'r', 'f', 'g', '8',
                                     'e', 'j', 'k', 'm', 'c', 'p', 'q', 'x',
                                     'o', 't', '1', 'u', 'w', 'i', 's', 'z',
                                     'a', '3', '4', '5', 'h', '7', '6', '9'};

/// adapted from i2pd
template <typename stack_t>
const char* base32z_encode(const std::vector<uint8_t>& value, stack_t& stack) {
    size_t ret = 0, pos = 1;
    uint32_t bits = 8, tmp = value[0];
    size_t len = value.size();
    while (ret < sizeof(stack) && (bits > 0 || pos < len)) {
        if (bits < 5) {
            if (pos < len) {
                tmp <<= 8;
                tmp |= value[pos] & 0xFF;
                pos++;
                bits += 8;
            } else // last byte
            {
                tmp <<= (5 - bits);
                bits = 5;
            }
        }

        bits -= 5;
        int ind = (tmp >> bits) & 0x1F;
        if (ret < sizeof(stack)) {
            stack[ret] = zbase32_alpha[ind];
            ret++;
        } else
            return nullptr;
    }
    return &stack[0];
}

std::string hex64_to_base32z(const std::string &src);

} // namespace util
