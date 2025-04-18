#include <catch2/catch.hpp>

#include <oxenmq/oxenmq.h>
#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/utils/time.hpp>
#include <oxenss/utils/random.hpp>
#include <random>

#include <oxenc/base64.h>

using namespace std::literals;
using namespace oxenss::crypto;

using ip_ports = std::tuple<oxen::quic::ipv4, uint16_t, uint16_t>;

using oxenss::snode::Contacts;

static oxenss::snode::contact create_dummy_contact() {
    const auto pk_x25519 = x25519_pubkey::from_hex(
            "66ab11bed0e6219e1f3aea9b9e33f89cf636d5db203ed4efb9090cdb15902414");
    const auto pk_ed25519 = ed25519_pubkey::from_hex(
            "a38418ae9af2fedb560f400953f91cefb91a7a7efc971edfa31744ce5c4e319a");

    return {oxen::quic::ipv4{"0.0.0.0"}, 8080, 8081, {2, 9, 0}, pk_ed25519, pk_x25519};
}

static void test_ip_update(
        Contacts& contacts, ip_ports old_addr, ip_ports new_addr, ip_ports expected) {
    auto tmp = create_dummy_contact();

    std::tie(tmp.ip, tmp.https_port, tmp.omq_quic_port) = old_addr;

    legacy_pubkey pk;
    for (int i = 0; i < 32; i += 8) {
        auto x = oxenss::util::rng()();
        static_assert(sizeof(x) == 8);
        std::memcpy(pk.data() + i, &x, 8);
    }
    contacts.update(pk, tmp);

    auto ct = contacts.find(pk);
    REQUIRE(ct);
    bool expect_contactable = std::get<0>(old_addr).addr != 0;
    CHECK(static_cast<bool>(*ct) == expect_contactable);
    CHECK(ct->contactable() == expect_contactable);

    std::tie(tmp.ip, tmp.https_port, tmp.omq_quic_port) = new_addr;

    contacts.update(pk, tmp);

    ct = contacts.find(pk);
    REQUIRE(ct);
    expect_contactable |= std::get<0>(new_addr).addr != 0;
    CHECK(static_cast<bool>(*ct) == expect_contactable);
    CHECK(ct->contactable() == expect_contactable);

    CHECK(ct->ip == std::get<0>(expected));
    CHECK(ct->https_port == std::get<1>(expected));
    CHECK(ct->omq_quic_port == std::get<2>(expected));
}

TEST_CASE("service nodes - updates IP address", "[service-nodes][updates]") {
    const auto fake_pk = oxenss::crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    oxenmq::OxenMQ omq;
    Contacts contacts{omq};

    const ip_ports default_ip{"0.0.0.0", 0, 0};
    const ip_ports ip1{"1.1.1.1", 123, 456};
    const ip_ports ip2{"1.2.3.4", 123, 456};

    // Should update
    test_ip_update(contacts, ip1, ip2, ip2);

    // Should update
    test_ip_update(contacts, default_ip, ip2, ip2);

    // Should NOT update with default ip
    test_ip_update(contacts, ip1, default_ip, ip1);
}

/// Check that we don't inadvertently change how we compute message hashes
TEST_CASE("service nodes - message hashing", "[service-nodes][messages]") {
    oxenss::user_pubkey pk;
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    const auto data = oxenc::from_base64(
            "CAES1gIKA1BVVBIPL2FwaS92MS9tZXNzYWdlGrsCCAYovfqZv4YvQq8CVwutUBbhRzZw80TvR6uTYMKg9DSag"
            "rtpeEpY31L7VxawfS8aSya0SiDa4J025SkjP13YX8g5pxgQ8Z6hgfNArMqr/tSijJ9miVKVDJ63YWE85O8kyW"
            "F8tdtZR5j0Vxb+JH5U8Rg1bp7ftKk3OSf7JJMcrUUrDnctQHe540zJ2OTDJ03DfubkX5NmKqEu5nhXGxeeDv3"
            "mTiL63fjtCvZYcikfjf6Nh1AX++HTgJ9SGoEIMastGUorFrmmXb2sbjHxNiJn0Radj/VzcA9VxYwBW5+AbGQ2"
            "d9+vvm7X+8vh+jIenJfjxf+8CWER+9adNfb4YUH07I+godNCV0O0J05gzqfKdT7J8MBZzFBtKrbk8oCagPpTs"
            "q/wZyYFKFKKD+q+zh704dYBILvs5yXUA96pIAA=");

    auto expected = "4sMyAuaZlMwww3oFvfhazfw7ASx/7TDtO+TVc8aAjHs";
    CHECK(oxenss::rpc::computeMessageHash(pk, oxenss::namespace_id::Default, data) == expected);
    CHECK(oxenss::rpc::compute_hash_blake2b_b64({pk.prefixed_raw() + data}) == expected);
}
