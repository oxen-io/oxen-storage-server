#include "serialization.h"
#include "service_node.h"

#include <catch2/catch.hpp>

#include <chrono>
#include <string>

using namespace oxen;
using oxen::storage::Item;

TEST_CASE("serialization - basic values", "[serialization]") {

    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s;
    const auto data = "data";
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{12'345'678ms};
    const auto ttl = 3456s;
    message_t msg{pub_key, data, hash, ttl, timestamp};
    std::string msg_serialized;
    serialize_message(msg_serialized, Item{msg});
    const auto expected_serialized = oxenmq::to_hex(pub_key) +
        "040000000000000068617368" // size+hash
        "040000000000000064617461" // size+data
        "00bc340000000000" // ttl
        "4e61bc0000000000" // timestamp
        "0000000000000000"s; // nonce
    CHECK(oxenmq::to_hex(msg_serialized) == expected_serialized);
    const std::vector<Item> inputs{Item{msg}, Item{msg}};
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
        CHECK(messages[i].expiration == timestamp + ttl);
    }
}

TEST_CASE("serialization - batch serialization", "[serialization]") {
    const auto pub_key =
        "054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e";
    std::string data(100000, 'x');
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    const auto ttl = 24h;
    message_t msg{pub_key, data, hash, ttl, timestamp};
    std::string buffer;
    serialize_message(buffer, Item{msg});
    const size_t num_messages = (SERIALIZATION_BATCH_SIZE / buffer.size()) + 1;
    std::vector<Item> inputs(num_messages, Item{msg});
    CHECK(serialize_messages(inputs).size() == 1);
    inputs.push_back(Item{msg});
    CHECK(serialize_messages(inputs).size() == 2);
}
