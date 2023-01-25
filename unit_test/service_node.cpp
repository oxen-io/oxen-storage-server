#include <catch2/catch.hpp>
#include <iostream>

#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/utils/time.hpp>

#include <oxenc/base64.h>

using namespace std::literals;
using namespace oxen::crypto;

static oxen::snode::sn_record create_dummy_sn_record() {
    const auto pk = legacy_pubkey::from_hex(
            "330e73449f6656cfe7816fa00d850af1f45884eab9e404026ca51f54b045e385");
    const auto pk_x25519 = x25519_pubkey::from_hex(
            "66ab11bed0e6219e1f3aea9b9e33f89cf636d5db203ed4efb9090cdb15902414");
    const auto pk_ed25519 = ed25519_pubkey::from_hex(
            "a38418ae9af2fedb560f400953f91cefb91a7a7efc971edfa31744ce5c4e319a");
    const std::string ip = "0.0.0.0";

    return {ip, 8080, 8081, pk, pk_ed25519, pk_x25519};
}

using ip_ports = std::tuple<const char*, uint16_t, uint16_t>;

static void test_ip_update(ip_ports old_addr, ip_ports new_addr, ip_ports expected) {
    using oxen::snode::sn_record;

    auto sn = create_dummy_sn_record();

    std::tie(sn.ip, sn.port, sn.omq_port) = old_addr;

    oxen::snode::SwarmInfo si{0, std::vector<sn_record>{sn}};
    std::vector<oxen::snode::SwarmInfo> current{{si}};

    std::tie(sn.ip, sn.port, sn.omq_port) = new_addr;

    oxen::snode::SwarmInfo si2{0, std::vector<sn_record>{sn}};
    std::vector<oxen::snode::SwarmInfo> incoming{{si2}};

    preserve_ips(incoming, current);

    CHECK(incoming[0].snodes[0].ip == std::get<0>(expected));
    CHECK(incoming[0].snodes[0].port == std::get<1>(expected));
    CHECK(incoming[0].snodes[0].omq_port == std::get<2>(expected));
}

TEST_CASE("service nodes - updates IP address", "[service-nodes][updates]") {
    auto sn = create_dummy_sn_record();

    const ip_ports default_ip{"0.0.0.0", 0, 0};
    const ip_ports ip1{"1.1.1.1", 123, 456};
    const ip_ports ip2{"1.2.3.4", 123, 456};

    // Should update
    test_ip_update(ip1, ip2, ip2);

    // Should update
    test_ip_update(default_ip, ip2, ip2);

    // Should NOT update with default ip
    test_ip_update(ip1, default_ip, ip1);
}

/// Check that we don't inadvertently change how we compute message hashes
TEST_CASE("service nodes - message hashing", "[service-nodes][messages]") {
    const std::chrono::system_clock::time_point timestamp{1616650862026ms};
    const auto expiry = timestamp + 48h;
    oxen::user_pubkey_t pk;
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    const auto data = oxenc::from_base64(
            "CAES1gIKA1BVVBIPL2FwaS92MS9tZXNzYWdlGrsCCAYovfqZv4YvQq8CVwutUBbhRzZw80TvR6uTYMKg9DSag"
            "rtpeEpY31L7VxawfS8aSya0SiDa4J025SkjP13YX8g5pxgQ8Z6hgfNArMqr/tSijJ9miVKVDJ63YWE85O8kyW"
            "F8tdtZR5j0Vxb+JH5U8Rg1bp7ftKk3OSf7JJMcrUUrDnctQHe540zJ2OTDJ03DfubkX5NmKqEu5nhXGxeeDv3"
            "mTiL63fjtCvZYcikfjf6Nh1AX++HTgJ9SGoEIMastGUorFrmmXb2sbjHxNiJn0Radj/VzcA9VxYwBW5+AbGQ2"
            "d9+vvm7X+8vh+jIenJfjxf+8CWER+9adNfb4YUH07I+godNCV0O0J05gzqfKdT7J8MBZzFBtKrbk8oCagPpTs"
            "q/wZyYFKFKKD+q+zh704dYBILvs5yXUA96pIAA=");

    auto expected = "4sMyAuaZlMwww3oFvfhazfw7ASx/7TDtO+TVc8aAjHs";
    CHECK(oxen::rpc::computeMessageHash(pk, oxen::namespace_id::Default, data) == expected);
    CHECK(oxen::rpc::compute_hash_blake2b_b64({pk.prefixed_raw() + data}) == expected);
}
