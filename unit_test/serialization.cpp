#include <oxenss/snode/serialization.h>
#include <oxenss/snode/service_node.h>
#include <oxenc/hex.h>

#include <catch2/catch.hpp>

#include <chrono>
#include <string>

using namespace oxen::snode;

TEST_CASE("v1 serialization - basic values", "[serialization]") {
    oxen::user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    const auto data = "da\x00ta"s;
    const auto hash = "hash\x00\x01\x02\x03"s;
    const std::chrono::system_clock::time_point timestamp{12'345'678ms};
    const auto expiry = timestamp + 3456s;
    std::vector<oxen::message> msgs;
    msgs.emplace_back(pub_key, hash, oxen::namespace_id::Default, timestamp, expiry, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    REQUIRE(serialized.size() == 1);
    const auto expected_serialized =
            "l"
            "33:\x05\x43\x68\x52\x00\x05\x78\x6b\x24\x9b\xcd\x46\x1d\x28\xf7\x5e\x56"  // pubkey
            "\x0e\xa7\x94\x01\x4e\xeb\x17\xfc\xf6\x00\x3f\x37\xd8\x76\x78\x3e"
            "8:hash\x00\x01\x02\x03"  // hash
            "i12345678e"              // timestamp
            "i15801678e"              // expiry
            "5:da\x00ta"              // data
            "e"s;
    CHECK(serialized.front() == "\x01l"s + expected_serialized + "e");

    msgs.push_back(msgs.front());
    const std::vector<std::string> batches = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(batches.size() == 1);
    REQUIRE(batches[0] == "\x01l"s + expected_serialized + expected_serialized + "e");

    const auto messages = deserialize_messages(batches[0]);
    CHECK(messages.size() == 2);
    for (int i = 0; i < messages.size(); ++i) {
        CHECK(messages[i].pubkey == pub_key);
        CHECK(messages[i].data == data);
        CHECK(messages[i].hash == hash);
        CHECK(messages[i].timestamp == timestamp);
        CHECK(messages[i].expiry == expiry);
    }
}

TEST_CASE("v1 serialization - batch serialization", "[serialization]") {
    oxen::user_pubkey_t pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    std::string data(100000, 'x');
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    const auto ttl = 24h;
    std::vector<oxen::message> msgs;
    msgs.emplace_back(pub_key, hash, oxen::namespace_id::Default, timestamp, timestamp + ttl, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    REQUIRE(serialized.size() == 1);
    auto first = serialized.front();
    const size_t num_messages = (SERIALIZATION_BATCH_SIZE / (serialized.front().size() - 2));
    msgs = {num_messages, msgs.front()};
    serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(serialized.size() == 1);
    msgs.push_back(msgs.front());
    serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(serialized.size() == 2);
}
