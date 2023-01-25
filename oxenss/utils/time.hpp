#pragma once

#include <chrono>
#include <cstdint>

namespace oxen {

inline int64_t to_epoch_ms(std::chrono::system_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

inline std::chrono::system_clock::time_point from_epoch_ms(int64_t t) {
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{t}};
}

}  // namespace oxen
