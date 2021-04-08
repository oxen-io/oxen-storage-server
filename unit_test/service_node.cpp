#include <boost/test/unit_test.hpp>
#include <iostream>

#include "swarm.h"
#include "request_handler.h"

BOOST_AUTO_TEST_SUITE(service_node_stuff)

static auto create_dummy_sn_record() -> sn_record_t {

    const std::string address =
        "0123456789012345678901234567890123456789012345678901";
    const std::string pk_hex =
        "330e73449f6656cfe7816fa00d850af1f45884eab9e404026ca51f54b045e385";
    const std::string pk_x25519 =
        "66ab11bed0e6219e1f3aea9b9e33f89cf636d5db203ed4efb9090cdb15902414";
    const std::string pk_x25519_bin = "";
    const std::string pk_ed25519 =
        "a38418ae9af2fedb560f400953f91cefb91a7a7efc971edfa31744ce5c4e319a";
    const std::string ip = "0.0.0.0";

    auto sn = sn_record_t{8080,      8081,          address,    pk_hex,
                          pk_x25519, pk_x25519_bin, pk_ed25519, ip};

    return sn;
}

static auto test_ip_update(const char* old_ip, const char* new_ip,
                           const char* expected_ip) -> void {

    auto sn = create_dummy_sn_record();

    sn.set_ip(old_ip);

    oxen::SwarmInfo si{0, std::vector<sn_record_t>{sn}};
    auto current = std::vector<oxen::SwarmInfo>{si};

    sn.set_ip(new_ip);

    oxen::SwarmInfo si2{0, std::vector<sn_record_t>{sn}};
    auto incoming = std::vector<oxen::SwarmInfo>{si2};

    auto new_records = apply_ips(current, incoming);

    BOOST_CHECK_EQUAL(new_records[0].snodes[0].ip(), expected_ip);
}

BOOST_AUTO_TEST_CASE(updates_ip_address) {

    auto sn = create_dummy_sn_record();

    const auto default_ip = "0.0.0.0";
    const auto ip1 = "1.1.1.1";
    const auto ip2 = "1.2.3.4";

    // Should update
    test_ip_update(ip1, ip2, ip2);

    // Should update
    test_ip_update(default_ip, ip2, ip2);

    // Should NOT update with default ip
    test_ip_update(ip1, default_ip, ip1);
}

/// Check that we don't inadvertently change how we compute message hashes
BOOST_AUTO_TEST_CASE(correctly_computes_hash) {

    const auto timestamp = "1616650862026";
    const auto ttl = "172800000";
    const auto pk = "05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48";
    const auto data = "CAES1gIKA1BVVBIPL2FwaS92MS9tZXNzYWdlGrsCCAYovfqZv4YvQq8CVwutUBbhRzZw80TvR6uTYMKg9DSagrtpeEpY31L7VxawfS8aSya0SiDa4J025SkjP13YX8g5pxgQ8Z6hgfNArMqr/tSijJ9miVKVDJ63YWE85O8kyWF8tdtZR5j0Vxb+JH5U8Rg1bp7ftKk3OSf7JJMcrUUrDnctQHe540zJ2OTDJ03DfubkX5NmKqEu5nhXGxeeDv3mTiL63fjtCvZYcikfjf6Nh1AX++HTgJ9SGoEIMastGUorFrmmXb2sbjHxNiJn0Radj/VzcA9VxYwBW5+AbGQ2d9+vvm7X+8vh+jIenJfjxf+8CWER+9adNfb4YUH07I+godNCV0O0J05gzqfKdT7J8MBZzFBtKrbk8oCagPpTsq/wZyYFKFKKD+q+zh704dYBILvs5yXUA96pIAA=";

    const auto hash = oxen::computeMessageHash(timestamp, ttl, pk, data);

    const auto expected = "dd5f46395dbab44c9d96711a68cd70e326c4a39d6ccce7a319b0262c18699d2044610196519ad7283e3defebcdf3bccd6499fce1254fdee661e68f0611dc3104";

    BOOST_CHECK_EQUAL(hash, expected);

}

BOOST_AUTO_TEST_SUITE_END()
