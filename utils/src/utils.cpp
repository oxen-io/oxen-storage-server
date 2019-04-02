#include "utils.hpp"

#include <vector>

namespace util {

constexpr uint8_t hex_to_nibble(const char & ch)
{
  return ( ch >= '0' && ch <= '9') ? ch - 48 : ((ch >= 'A' && ch <= 'F' ) ? ch - 55 : ((ch >= 'a' && ch <= 'f' ) ? ch - 87 : 0));
}

constexpr uint8_t hexpair_to_byte(const char & hi, const char & lo)
{
  return hex_to_nibble(hi) << 4 | hex_to_nibble(lo);
}

std::string hex64_to_base32z(const std::string &src)
{
  // decode to binary
  std::vector<uint8_t> bin;
  // odd sized is invalid
  if(src.size() & 1)
    return "";
  {
    auto itr = src.begin();
    while(itr != src.end())
    {
      const char hi = *itr;
      ++itr;
      const char lo = *itr;
      ++itr;
      bin.emplace_back(hexpair_to_byte(hi,lo));
    }
  }
  // encode to base32z
  char buf[64] = {0};
  std::string result;
  if (char const *dest = base32z_encode(bin, buf))
    result = dest;

  return result;
}

bool parseTTL(const std::string& ttlString, uint64_t& ttl) {
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
