#pragma once

#include <functional>
#include <string>
#include <vector>
#include <oxenss/common/message.h>

namespace oxenss::snode {

// As soon as we exceed this we stop the current serialization message and begin a new one.  (And so
// our messages end up a little larger than this, but still well under the 10MiB limit).
inline constexpr size_t SERIALIZATION_BATCH_SIZE = 9'000'000;

// Newer serialization version based on bt-encoding.
inline constexpr uint8_t SERIALIZATION_VERSION_BT = 1;

std::vector<std::string> serialize_messages(
        std::function<const message*()> next_msg, uint8_t version);

template <typename It>
std::vector<std::string> serialize_messages(It begin, It end, uint8_t version) {
    return serialize_messages(
            [&begin, &end]() -> const message* { return begin == end ? nullptr : &*begin++; },
            version);
}

std::vector<message> deserialize_messages(std::string_view blob);

}  // namespace oxenss::snode
