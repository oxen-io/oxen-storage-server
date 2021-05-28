#include "serialization.h"
#include "service_node.h"

#include <catch2/catch.hpp>

#include <string>

using namespace oxen;

TEST_CASE("serialization - basic values", "[serialization]") {

    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s;
    const auto data = "data";
    const auto hash = "hash";
    const uint64_t timestamp = 12345678;
    const uint64_t ttl = 3456000;
    message_t msg{pub_key, data, hash, ttl, timestamp};
    std::string msg_serialized;
    serialize_message(msg_serialized, msg);
    const auto expected_serialized = oxenmq::to_hex(pub_key) +
        "040000000000000068617368" // size+hash
        "040000000000000064617461" // size+data
        "00bc340000000000" // ttl
        "4e61bc0000000000" // timestamp
        "0000000000000000"s; // nonce
    CHECK(oxenmq::to_hex(msg_serialized) == expected_serialized);
    const std::vector<message_t> inputs{msg, msg};
    const std::vector<std::string> batches = serialize_messages(inputs);
    CHECK(batches.size() == 1);
    CHECK(oxenmq::to_hex(batches[0]) == expected_serialized + expected_serialized);

    const auto messages = deserialize_messages(batches[0]);
    CHECK(messages.size() == 2);
    for (int i = 0; i < messages.size(); ++i) {
        CHECK(messages[i].pub_key == pub_key);
        CHECK(messages[i].data == data);
        CHECK(messages[i].hash == hash);
        CHECK(messages[i].timestamp == timestamp);
        CHECK(messages[i].ttl == ttl);
    }
}

TEST_CASE("serialization - batch serialization", "[serialization]") {
    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e";
    const auto data = "data";
    const auto hash = "hash";
    const uint64_t timestamp = 12345678;
    const uint64_t ttl = 3456000;
    message_t msg{pub_key, data, hash, ttl, timestamp};
    std::string buffer;
    serialize_message(buffer, msg);
    const size_t num_messages = (500000 / buffer.size()) + 10;
    std::vector<message_t> inputs;
    for (int i = 0; i < num_messages; ++i)
        inputs.push_back(msg);
    const std::vector<std::string> batches = serialize_messages(inputs);
    CHECK(batches.size() == 2);
}
