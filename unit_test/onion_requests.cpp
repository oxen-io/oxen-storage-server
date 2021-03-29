#include <boost/test/unit_test.hpp>
#include <iostream>
#include <ostream>

#include "onion_processing.h"

using namespace oxen;

BOOST_AUTO_TEST_SUITE(onion_requests)

constexpr const char* plaintext = "plaintext";
constexpr const char* ciphertext = "ciphertext";

// Provided "headers", so the request terminates
// at a service node.
BOOST_AUTO_TEST_CASE(final_destination) {
    const std::string inner_json = R"#({
        "headers": "something"
    })#";

    CiphertextPlusJson combined{ ciphertext, inner_json };

    auto res = process_inner_request(combined, plaintext);

    auto expected = FinalDestinationInfo {
        ciphertext
    };

    BOOST_CHECK_EQUAL(std::holds_alternative<FinalDestinationInfo>(res), true);
    BOOST_CHECK_EQUAL(*std::get_if<FinalDestinationInfo>(&res), expected);

}

// Provided "host", so the request should go
// to an extrenal server. Default values will
// be used for port and protocol.
BOOST_AUTO_TEST_CASE(relay_to_server_legacy) {
    const std::string inner_json = R"#({
        "host": "host",
        "target": "target"
    })#";

    CiphertextPlusJson combined{ ciphertext, inner_json };

    auto res = process_inner_request(combined, plaintext);

    uint16_t port = 443;
    std::string protocol = "https";

    auto expected = RelayToServerInfo {
        plaintext,
        "host",
        port,
        protocol,
        "target"
    };

    BOOST_CHECK_EQUAL(std::holds_alternative<RelayToServerInfo>(res), true);
    BOOST_CHECK_EQUAL(*std::get_if<RelayToServerInfo>(&res), expected);

}

// Provided "host", so the request should go
// to an extrenal server.
BOOST_AUTO_TEST_CASE(relay_to_server) {
    const std::string inner_json = R"#({
        "host": "host",
        "target": "target",
        "port": 80,
        "protocol": "http"
    })#";

    CiphertextPlusJson combined{ ciphertext, inner_json };

    auto res = process_inner_request(combined, plaintext);

    uint16_t port = 80;
    std::string protocol = "http";

    auto expected = RelayToServerInfo {
        plaintext,
        "host",
        port,
        protocol,
        "target"
    };

    BOOST_CHECK_EQUAL(std::holds_alternative<RelayToServerInfo>(res), true);
    BOOST_CHECK_EQUAL(*std::get_if<RelayToServerInfo>(&res), expected);

}

/// No "host" or "headers", so we forward
/// the request to another node
BOOST_AUTO_TEST_CASE(relay_to_node) {

    const std::string inner_json = R"#({
        "destination": "destination",
        "ephemeral_key": "ephemeral_key"
    })#";

    CiphertextPlusJson combined{ ciphertext, inner_json };

    auto res = process_inner_request(combined, plaintext);

    auto expected = RelayToNodeInfo {
        ciphertext,
        "ephemeral_key",
        "destination"
    };

    BOOST_CHECK_EQUAL(std::holds_alternative<RelayToNodeInfo>(res), true);
    BOOST_CHECK_EQUAL(*std::get_if<RelayToNodeInfo>(&res), expected);

}

BOOST_AUTO_TEST_SUITE_END()