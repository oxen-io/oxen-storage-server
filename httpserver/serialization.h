#pragma once

#include <functional>
#include <string>
#include <vector>

namespace oxen {

struct message;

inline constexpr size_t SERIALIZATION_BATCH_SIZE = 9'000'000;

// The oldest serialization version we support (as of this version of SS)
inline constexpr uint8_t SERIALIZATION_VERSION_COMPAT = 0;

// The next serialization version we support, if any (we use this on testnet, and often with a HF
// version guard for upgrades).
inline constexpr uint8_t SERIALIZATION_VERSION_NEXT = 1;

std::vector<std::string> serialize_messages(std::function<const message*()> next_msg, uint8_t version);

template <typename It>
std::vector<std::string> serialize_messages(It begin, It end, uint8_t version) {
    return serialize_messages([&begin, &end]() mutable -> const message* {
        return begin == end ? nullptr : &*begin++;
    }, version);
}

std::vector<message> deserialize_messages(std::string_view blob);

} // namespace oxen
