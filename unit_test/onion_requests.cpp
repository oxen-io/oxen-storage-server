#include <boost/test/unit_test.hpp>
#include <iostream>
#include <ostream>

#include "onion_processing.h"

using namespace oxen;

BOOST_AUTO_TEST_SUITE(onion_requests)

constexpr const char* ciphertext = "ciphertext";
const auto prefix = "\x0a\0\0\0ciphertext"s;

// Provided "headers", so the request terminates
// at a service node.
BOOST_AUTO_TEST_CASE(final_destination) {
    auto data = prefix + R"#({
        "headers": "something"
    })#";

    auto res = process_inner_request(data);

    auto expected = FinalDestinationInfo {
        ciphertext
    };

    BOOST_REQUIRE(std::holds_alternative<FinalDestinationInfo>(res));
    BOOST_CHECK_EQUAL(*std::get_if<FinalDestinationInfo>(&res), expected);

}

// Provided "host", so the request should go
// to an extrenal server. Default values will
// be used for port and protocol.
BOOST_AUTO_TEST_CASE(relay_to_server_legacy) {
    auto data = prefix + R"#({
        "host": "host",
        "target": "target"
    })#";

    auto res = process_inner_request(data);

    uint16_t port = 443;
    std::string protocol = "https";

    auto expected = RelayToServerInfo {
        data,
        "host",
        port,
        protocol,
        "target"
    };

    BOOST_REQUIRE(std::holds_alternative<RelayToServerInfo>(res));
    BOOST_CHECK_EQUAL(*std::get_if<RelayToServerInfo>(&res), expected);

}

// Provided "host", so the request should go
// to an extrenal server.
BOOST_AUTO_TEST_CASE(relay_to_server) {
    auto data = prefix + R"#({
        "host": "host",
        "target": "target",
        "port": 80,
        "protocol": "http"
    })#";

    auto res = process_inner_request(data);

    uint16_t port = 80;
    std::string protocol = "http";

    auto expected = RelayToServerInfo {
        data,
        "host",
        port,
        protocol,
        "target"
    };

    BOOST_REQUIRE(std::holds_alternative<RelayToServerInfo>(res));
    BOOST_CHECK_EQUAL(*std::get_if<RelayToServerInfo>(&res), expected);

}

/// No "host" or "headers", so we forward
/// the request to another node
BOOST_AUTO_TEST_CASE(relay_to_node) {

    auto data = prefix + R"#({
        "destination": "ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000",
        "ephemeral_key": "0000111122223333444455556666777788889999000011112222333344445555"
    })#";

    auto res = process_inner_request(data);

    auto expected = RelayToNodeInfo {
        ciphertext,
        x25519_pubkey::from_hex("0000111122223333444455556666777788889999000011112222333344445555"),
        EncryptType::aes_gcm,
        ed25519_pubkey::from_hex("ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000")
    };

    BOOST_REQUIRE(std::holds_alternative<RelayToNodeInfo>(res));
    BOOST_CHECK_EQUAL(*std::get_if<RelayToNodeInfo>(&res), expected);

}

BOOST_AUTO_TEST_CASE(correctly_filters_urls) {

    BOOST_CHECK(is_server_url_allowed("/loki/v3/lsrpc"));
    BOOST_CHECK(is_server_url_allowed("/loki/oxen/v4/lsrpc"));
    BOOST_CHECK(is_server_url_allowed("/oxen/v3/lsrpc"));

    BOOST_CHECK(!is_server_url_allowed("/not_loki/v3/lsrpc"));
    BOOST_CHECK(!is_server_url_allowed("/loki/v3"));
    BOOST_CHECK(!is_server_url_allowed("/loki/v3/lsrpc?foo=bar"));

}

BOOST_AUTO_TEST_SUITE_END()
