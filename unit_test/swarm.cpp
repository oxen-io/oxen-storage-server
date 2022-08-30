#include <catch2/catch.hpp>
#include <iostream>

#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/utils/time.hpp>

#include <oxenc/base64.h>

using namespace std::literals;

using ip_ports = std::tuple<const char*, uint16_t, uint16_t>;

TEST_CASE("swarm - pubkey to swarm space", "[swarm]") {
    oxen::user_pubkey_t pk;
    REQUIRE(pk.load("053506f4a71324b7dd114eddbf4e311f39dde243e1f2cb97c40db1961f70ebaae8"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 17589930838143112648ULL);
    REQUIRE(pk.load("05cf27da303a50ac8c4b2d43d27259505c9bcd73fc21cf2a57902c3d050730b604"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 10370619079776428163ULL);
    REQUIRE(pk.load("03d3511706b8b34f6e8411bf07bd22ba6b2435ca56846fbccf6eb1e166a6cd15cc"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 2144983569669512198ULL);
    REQUIRE(pk.load("ff0f06693428fca9102a451e3f28d9cc743d8ea60a89ab6aa69eb119470c11cbd3"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 9690840703409570833ULL);
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 4532060000165252872ULL);
    REQUIRE(pk.load("05eeeeeeeeeeeeeeee777777777777777711111111111111118888888888888888"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 0);
    REQUIRE(pk.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 0);
    REQUIRE(pk.load("05fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 1);
    REQUIRE(pk.load("05ffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffff"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 1ULL << 63);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == (uint64_t)-1);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000123456789abcdef"));
    CHECK(oxen::snode::pubkey_to_swarm_space(pk) == 0x0123456789abcdefULL);
}

TEST_CASE("service nodes - pubkey to swarm id") {
    std::vector<oxen::snode::SwarmInfo> swarms{
            {100, {}}, {200, {}}, {300, {}}, {399, {}}, {498, {}}, {596, {}}, {694, {}}};

    oxen::user_pubkey_t pk;

    // Exact matches:
    // 0x64 = 100, 0xc8 = 200, 0x1f2 = 498
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000064"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000c8"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001f2"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 498);

    // Nearest
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000001"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    // Nearest, with wraparound
    // 0x8000... is closest to the top value
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000008000000000000000"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 694);

    // 0xa000... is closest (via wraparound) to the smallest
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000a000000000000000"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    // This is the invalid swarm id for swarms, but should still work for a client
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000fffffffffffffffe"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    // Midpoint tests; we prefer the lower value when exactly in the middle between two swarms.
    // 0x96 = 150
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000095"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000096"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000097"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 200);

    // 0xfa = 250
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000f9"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000fa"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000fb"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 300);

    // 0x15d = 349
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000000000000000015d"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 300);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000000000000000015e"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 399);

    // 0x1c0 = 448
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001c0"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 399);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001c1"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 498);

    // 0x223 = 547
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000222"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 498);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000223"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 498);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000224"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 596);

    // 0x285 = 645
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000285"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 596);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000286"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 694);

    // 0x800....d is the midpoint between 694 and 100 (the long way).  We always round "down" (which
    // in this case, means wrapping to the largest swarm).
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018c"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 694);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018d"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 694);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018e"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 100);

    // With a swarm at -20 the midpoint is now 40 (=0x28).  When our value is the *low* value we
    // prefer the *last* swarm in the case of a tie (while consistent with the general case of
    // preferring the left edge, it means we're inconsistent with the other wraparound case, above.
    // *sigh*).
    swarms.push_back({(uint64_t)-20, {}});
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000027"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == swarms.back().swarm_id);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000028"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == swarms.back().swarm_id);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000029"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == swarms.front().swarm_id);

    // The code used to have a broken edge case if we have a swarm at zero and a client at max-u64
    // because of an overflow in how the distance is calculated (the first swarm will be calculated
    // as max-u64 away, rather than 1 away), and so the id always maps to the highest swarm (even
    // though 0xfff...fe maps to the lowest swarm; the first check here, then, would fail.
    swarms.insert(swarms.begin(), {0, {}});
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 0);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000fffffffffffffffe"));
    CHECK(get_swarm_by_pk(swarms, pk)->swarm_id == 0);
}
