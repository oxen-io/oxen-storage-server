#include <boost/test/unit_test.hpp>
#include <iostream>
#include <ostream>

#include "ip_utils.h"

using namespace oxen;

BOOST_AUTO_TEST_SUITE(ip_utils)

void should_be_public(const char* addr_str) {
    auto addr = boost::asio::ip::make_address_v4(addr_str);
    BOOST_CHECK_EQUAL(is_ip_public(addr), true);
}

void should_not_be_public(const char* addr_str) {
    auto addr = boost::asio::ip::make_address_v4(addr_str);
    BOOST_CHECK_EQUAL(is_ip_public(addr), false);
}

BOOST_AUTO_TEST_CASE(netmask) {
    BOOST_CHECK_EQUAL(netmask_ipv4_bits(8), uint32_t{0xFF000000});
}

BOOST_AUTO_TEST_CASE(checks_if_ip_public) {

    should_not_be_public("192.168.1.111");
    should_not_be_public("10.40.11.6");
    should_not_be_public("127.0.0.1");
    should_not_be_public("0.0.0.0");

    should_be_public("1.1.1.1");
    should_be_public("8.8.6.6");
    should_be_public("141.55.12.99");
    should_be_public("79.12.3.4");
}

BOOST_AUTO_TEST_SUITE_END()