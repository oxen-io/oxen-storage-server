#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include "formattable.h"

namespace oxenss {

enum class namespace_id : int16_t {
    Default = 0,  // Ordinary Session messages
    Min = -32768,
    Max = 32767,
    SessionSync = 5,     // Session sync data for imports & multidevice syncing
    ClosedV2 = 3,        // Reserved for future Session closed group implementations
    LegacyClosed = -10,  // For "old" closed group messages; allows unauthenticated retrieval
};

constexpr bool is_public_namespace(namespace_id ns) {
    return static_cast<std::underlying_type_t<namespace_id>>(ns) % 10 == 0;
}

constexpr auto to_int(namespace_id ns) {
    return static_cast<std::underlying_type_t<namespace_id>>(ns);
}

std::string to_string(namespace_id ns);

constexpr auto NAMESPACE_MIN = to_int(namespace_id::Min);
constexpr auto NAMESPACE_MAX = to_int(namespace_id::Max);

template <>
inline constexpr bool to_string_formattable<namespace_id> = true;

}  // namespace oxenss
