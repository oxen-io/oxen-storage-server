#include "ip_utils.h"

#include <tuple>
#include <boost/endian/conversion.hpp>

namespace oxen {

/// Most of this file is copied from lokid (https://github.com/oxen-io/oxen-core/pull/1393)

uint32_t netmask_ipv4_bits(int prefix) {
    if (prefix) {
        return ~((1 << (32 - prefix)) - 1);
    } else {
        return uint32_t{0};
    }
}

uint32_t ipaddr_ipv4_bits(const uint8_t a, const uint8_t b, const uint8_t c,
                          const uint8_t d) {
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

std::tuple<uint32_t, uint32_t> FromIPv4(const uint8_t a, const uint8_t b,
                                        const uint8_t c, const uint8_t d,
                                        const uint32_t netmask) {
    return std::tuple<uint32_t, uint32_t>{ipaddr_ipv4_bits(a, b, c, d),
                                          netmask_ipv4_bits(netmask)};
}

// clang-format off
std::array bogonRanges = { FromIPv4(0, 0, 0, 0, 8),
                           FromIPv4(10, 0, 0, 0, 8),
                           FromIPv4(100, 64, 0, 0, 10),
                           FromIPv4(127, 0, 0, 0, 8),
                           FromIPv4(169, 254, 0, 0, 16),
                           FromIPv4(172, 16, 0, 0, 12),
                           FromIPv4(192, 0, 0, 0, 24),
                           FromIPv4(192, 0, 2, 0, 24),
                           FromIPv4(192, 88, 99, 0, 24),
                           FromIPv4(192, 168, 0, 0, 16),
                           FromIPv4(198, 18, 0, 0, 15),
                           FromIPv4(198, 51, 100, 0, 24),
                           FromIPv4(203, 0, 113, 0, 24),
                           FromIPv4(224, 0, 0, 0, 4),
                           FromIPv4(240, 0, 0, 0, 4) };
// clang-format on

static bool is_ip_public_inner(const uint32_t ip)
{
  for(const auto ipRange: bogonRanges) {
    uint32_t netstart = (std::get<0>(ipRange) & std::get<1>(ipRange)); // first ip in subnet
    uint32_t netend = (netstart | ~std::get<1>(ipRange)); // last ip in subnet
    if ((ip >= netstart) && (ip <= netend))
      return false;
  }
  return true;
}

bool is_ip_public(boost::asio::ip::address_v4 addr) {

  uint32_t bytes = addr.to_ulong();

  boost::endian::native_to_little_inplace(bytes);

  return is_ip_public_inner(bytes);

}

} // namespace oxen