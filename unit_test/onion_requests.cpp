#include <catch2/catch.hpp>
#include <iostream>
#include <ostream>

#include <oxenss/rpc/onion_processing.h>

using namespace oxenss::rpc;
using namespace oxenss::crypto;
using namespace std::literals;

constexpr const char* ciphertext = "ciphertext";
const auto prefix = "\x0a\0\0\0ciphertext"s;

// Provided "headers", so the request terminates
// at a service node.
TEST_CASE("onion request - final destination", "[onion][final]") {
    auto data = prefix + R"#({
        "headers": "something"
    })#";

    auto res = process_inner_request(data);

    auto expected = FinalDestinationInfo{ciphertext};

    REQUIRE(std::holds_alternative<FinalDestinationInfo>(res));
    CHECK(*std::get_if<FinalDestinationInfo>(&res) == expected);
}

// Provided "host", so the request should go
// to an external server. Default values will
// be used for port and protocol.
TEST_CASE("onion request - relay to server (legacy)", "[onion][relay]") {
    auto data = prefix + R"#({
        "host": "host",
        "target": "target"
    })#";

    auto res = process_inner_request(data);

    uint16_t port = 443;
    std::string protocol = "https";

    auto expected = RelayToServerInfo{data, "host", port, protocol, "target"};

    REQUIRE(std::holds_alternative<RelayToServerInfo>(res));
    CHECK(*std::get_if<RelayToServerInfo>(&res) == expected);
}

// Provided "host", so the request should go
// to an external server.
TEST_CASE("onion request - relay to server", "[onion][relay]") {
    auto data = prefix + R"#({
        "host": "host",
        "target": "target",
        "port": 80,
        "protocol": "http"
    })#";

    auto res = process_inner_request(data);

    uint16_t port = 80;
    std::string protocol = "http";

    auto expected = RelayToServerInfo{data, "host", port, protocol, "target"};

    REQUIRE(std::holds_alternative<RelayToServerInfo>(res));
    CHECK(*std::get_if<RelayToServerInfo>(&res) == expected);
}

/// No "host" or "headers", so we forward
/// the request to another node
TEST_CASE("onion request - relay to snode", "[onion][snode]") {
    auto data = prefix + R"#({
        "destination": "ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000",
        "ephemeral_key": "0000111122223333444455556666777788889999000011112222333344445555"
    })#";

    auto res = process_inner_request(data);

    auto expected = RelayToNodeInfo{
            ciphertext,
            x25519_pubkey::from_hex("00001111222233334444555566667777888899990000111122223333444455"
                                    "55"),
            EncryptType::aes_gcm,
            ed25519_pubkey::from_hex("ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110"
                                     "000")};

    REQUIRE(std::holds_alternative<RelayToNodeInfo>(res));
    CHECK(*std::get_if<RelayToNodeInfo>(&res) == expected);
}

TEST_CASE("onion request - url target filtering", "[onion][relay]") {
    CHECK(is_onion_url_target_allowed("/loki/v3/lsrpc"));
    CHECK(is_onion_url_target_allowed("/loki/oxen/v4/lsrpc"));
    CHECK(is_onion_url_target_allowed("/oxen/v3/lsrpc"));

    CHECK_FALSE(is_onion_url_target_allowed("/not_loki/v3/lsrpc"));
    CHECK_FALSE(is_onion_url_target_allowed("/loki/v3"));
    CHECK_FALSE(is_onion_url_target_allowed("/loki/v3/lsrpc?foo=bar"));
}
