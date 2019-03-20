#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <algorithm>

namespace util {

bool parseTTL(const std::string& ttlString, uint64_t& ttl);

template <typename stack_t>
const char* base32z_encode(const std::vector<uint8_t>& value, stack_t &stack);

} // namespace util
