#pragma once

#include <string>
#include <string_view>
#include <stdint.h>

namespace oxenss {
enum class Serialise {
    Read,
    Write,
};

struct SerialiseBTResult {
    bool success;
    std::string write_payload;
    std::string error;
};

constexpr uint64_t FNV1A64_SEED = 14695981039346656037ULL;

inline uint64_t fnv1a64_hasher(std::string_view bytes, uint64_t hash) {
    for (size_t i = 0; i < bytes.size(); i++)
        hash = (bytes[i] ^ hash) * 1099511628211 /*FNV Prime*/;
    return hash;
}

};  // namespace oxenss
