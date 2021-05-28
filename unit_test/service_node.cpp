#include <catch2/catch.hpp>
#include <iostream>

#include "oxend_key.h"
#include "swarm.h"
#include "request_handler.h"

static auto create_dummy_sn_record() -> oxen::sn_record_t {

    const auto pk = oxen::legacy_pubkey::from_hex(
        "330e73449f6656cfe7816fa00d850af1f45884eab9e404026ca51f54b045e385");
    const auto pk_x25519 = oxen::x25519_pubkey::from_hex(
        "66ab11bed0e6219e1f3aea9b9e33f89cf636d5db203ed4efb9090cdb15902414");
    const auto pk_ed25519 = oxen::ed25519_pubkey::from_hex(
        "a38418ae9af2fedb560f400953f91cefb91a7a7efc971edfa31744ce5c4e319a");
    const std::string ip = "0.0.0.0";

    return {ip, 8080, 8081, pk, pk_ed25519, pk_x25519};
}

using ip_ports = std::tuple<const char*, uint16_t, uint16_t>;

static auto test_ip_update(ip_ports old_addr, ip_ports new_addr,
                           ip_ports expected) -> void {

    using oxen::sn_record_t;

    auto sn = create_dummy_sn_record();

    std::tie(sn.ip, sn.port, sn.omq_port) = old_addr;

    oxen::SwarmInfo si{0, std::vector<sn_record_t>{sn}};
    auto current = std::vector<oxen::SwarmInfo>{si};

    std::tie(sn.ip, sn.port, sn.omq_port) = new_addr;

    oxen::SwarmInfo si2{0, std::vector<sn_record_t>{sn}};
    auto incoming = std::vector<oxen::SwarmInfo>{si2};

    auto new_records = apply_ips(current, incoming);

    CHECK(new_records[0].snodes[0].ip == std::get<0>(expected));
    CHECK(new_records[0].snodes[0].port == std::get<1>(expected));
    CHECK(new_records[0].snodes[0].omq_port == std::get<2>(expected));
}

TEST_CASE("service nodes - updates IP address", "[service-nodes][updates]") {

    auto sn = create_dummy_sn_record();

    const auto default_ip = ip_ports{"0.0.0.0", 0, 0};
    const auto ip1 = ip_ports{"1.1.1.1", 123, 456};
    const auto ip2 = ip_ports{"1.2.3.4", 123, 456};

    // Should update
    test_ip_update(ip1, ip2, ip2);

    // Should update
    test_ip_update(default_ip, ip2, ip2);

    // Should NOT update with default ip
    test_ip_update(ip1, default_ip, ip1);
}

/// Check that we don't inadvertently change how we compute message hashes
TEST_CASE("service nodes - message hashing", "[service-nodes][messages]") {

    const auto timestamp = "1616650862026";
    const auto ttl = "172800000";
    const auto pk = "05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48";
    const auto data = "CAES1gIKA1BVVBIPL2FwaS92MS9tZXNzYWdlGrsCCAYovfqZv4YvQq8CVwutUBbhRzZw80TvR6uTYMKg9DSagrtpeEpY31L7VxawfS8aSya0SiDa4J025SkjP13YX8g5pxgQ8Z6hgfNArMqr/tSijJ9miVKVDJ63YWE85O8kyWF8tdtZR5j0Vxb+JH5U8Rg1bp7ftKk3OSf7JJMcrUUrDnctQHe540zJ2OTDJ03DfubkX5NmKqEu5nhXGxeeDv3mTiL63fjtCvZYcikfjf6Nh1AX++HTgJ9SGoEIMastGUorFrmmXb2sbjHxNiJn0Radj/VzcA9VxYwBW5+AbGQ2d9+vvm7X+8vh+jIenJfjxf+8CWER+9adNfb4YUH07I+godNCV0O0J05gzqfKdT7J8MBZzFBtKrbk8oCagPpTsq/wZyYFKFKKD+q+zh704dYBILvs5yXUA96pIAA=";

    const auto hash = oxen::computeMessageHash({timestamp, ttl, pk, data}, true);

    const auto expected = "dd5f46395dbab44c9d96711a68cd70e326c4a39d6ccce7a319b0262c18699d2044610196519ad7283e3defebcdf3bccd6499fce1254fdee661e68f0611dc3104";

    CHECK(hash == expected);

    CHECK(
            oxen::computeMessageHash({timestamp, ttl, pk, data}, false) ==
            oxenmq::from_hex(expected));

}
