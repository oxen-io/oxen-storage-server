#pragma once

#include <cstdint>
#include <boost/asio.hpp>

namespace oxen {

uint32_t netmask_ipv4_bits(int prefix);

uint32_t ipaddr_ipv4_bits(const uint8_t a, const uint8_t b, const uint8_t c,
                          const uint8_t d);

bool is_ip_public(boost::asio::ip::address_v4 addr);

} // namespace oxen