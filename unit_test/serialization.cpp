#include "serialization.h"
#include "service_node.h"

#include <boost/test/unit_test.hpp>

#include <string>

using namespace loki;

BOOST_AUTO_TEST_SUITE(serialization)

BOOST_AUTO_TEST_CASE(it_serializes_and_deserializes) {

    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e";
    const auto data = "data";
    const auto hash = "hash";
    const uint64_t timestamp = 12345678;
    const uint64_t ttl = 3456000;
    const auto nonce = "nonce";
    const size_t pk_size = 66;
    message_t msg{pub_key, data, hash, ttl, timestamp, nonce};
    const std::vector<message_t> inputs{msg, msg};
    const std::vector<std::string> batches = serialize_messages(inputs);
    BOOST_CHECK_EQUAL(batches.size(), 1);

    const auto messages = deserialize_messages(batches[0]);
    BOOST_CHECK_EQUAL(messages.size(), 2);
    for (int i = 0; i < messages.size(); ++i) {
        BOOST_CHECK_EQUAL(messages[i].pub_key, pub_key);
        BOOST_CHECK_EQUAL(messages[i].data, data);
        BOOST_CHECK_EQUAL(messages[i].hash, hash);
        BOOST_CHECK_EQUAL(messages[i].timestamp, timestamp);
        BOOST_CHECK_EQUAL(messages[i].ttl, ttl);
        BOOST_CHECK_EQUAL(messages[i].nonce, nonce);
    }
}

BOOST_AUTO_TEST_CASE(it_serialises_in_batches) {
    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e";
    const auto data = "data";
    const auto hash = "hash";
    const uint64_t timestamp = 12345678;
    const uint64_t ttl = 3456000;
    const auto nonce = "nonce";
    message_t msg{pub_key, data, hash, ttl, timestamp, nonce};
    std::string buffer;
    serialize_message(buffer, msg);
    const size_t num_messages = (500000 / buffer.size()) + 10;
    std::vector<message_t> inputs;
    for (int i = 0; i < num_messages; ++i)
        inputs.push_back(msg);
    const std::vector<std::string> batches = serialize_messages(inputs);
    BOOST_CHECK_EQUAL(batches.size(), 2);
}
BOOST_AUTO_TEST_SUITE_END()
