#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace oxen {

extern const std::array<uint16_t, 3> STORAGE_SERVER_VERSION;

extern const std::string_view STORAGE_SERVER_VERSION_STRING;
extern const std::string_view STORAGE_SERVER_GIT_HASH_STRING;
extern const std::string_view STORAGE_SERVER_BUILD_TIME;
extern const std::string_view STORAGE_SERVER_VERSION_INFO;

}  // namespace oxen
