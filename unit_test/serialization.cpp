#include <oxenss/snode/serialization.h>
#include <oxenss/snode/service_node.h>
#include <oxenc/hex.h>
#include <oxenss/utils/string_utils.hpp>

#include <catch2/catch.hpp>

#include <fmt/chrono.h>
#include <chrono>
#include <string>

using namespace oxenss::snode;

TEST_CASE("v1 serialization - basic values", "[serialization]") {
    oxenss::user_pubkey pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    const auto data = "da\x00ta"s;
    const auto hash = "hash\x00\x01\x02\x03"s;
    const std::chrono::system_clock::time_point timestamp{12'345'678ms};
    const auto expiry = timestamp + 3456s;
    std::vector<oxenss::message> msgs;
    msgs.emplace_back(pub_key, hash, oxenss::namespace_id::UserProfile, timestamp, expiry, data);
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
            "i2e"                     // namespace
            "e"s;
    CHECK(serialized.front() == "\x01l"s + expected_serialized + "e");

    msgs.push_back(msgs.front());
    const std::vector<std::string> batches = serialize_messages(msgs.begin(), msgs.end(), 1);
    CHECK(batches.size() == 1);
    REQUIRE(batches[0] == "\x01l"s + expected_serialized + expected_serialized + "e");

    const auto messages = deserialize_messages(batches[0]);
    CHECK(messages.size() == 2);
    for (size_t i = 0; i < messages.size(); ++i) {
        CHECK(messages[i].pubkey == pub_key);
        CHECK(messages[i].data == data);
        CHECK(messages[i].hash == hash);
        CHECK(messages[i].timestamp == timestamp);
        CHECK(messages[i].expiry == expiry);
        CHECK(messages[i].msg_namespace == oxenss::namespace_id::UserProfile);
    }
}

TEST_CASE("v1 serialization - batch serialization", "[serialization]") {
    oxenss::user_pubkey pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));
    std::string data(100000, 'x');
    const auto hash = "hash";
    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    const auto ttl = 24h;
    std::vector<oxenss::message> msgs;
    msgs.emplace_back(
            pub_key, hash, oxenss::namespace_id::GroupInfo, timestamp, timestamp + ttl, data);
    auto serialized = serialize_messages(msgs.begin(), msgs.end(), 1);
    REQUIRE(serialized.size() == 1);
    auto first = serialized.front();
    const size_t num_messages = (SERIALIZATION_BATCH_SIZE / (serialized.front().size() - 2)) + 1;
    msgs = {num_messages, msgs.front()};
    serialized = serialize_messages(msgs.begin(), msgs.end(), SERIALIZATION_VERSION_BT);
    CHECK(serialized.size() == 1);
    msgs.push_back(msgs.front());
    serialized = serialize_messages(msgs.begin(), msgs.end(), SERIALIZATION_VERSION_BT);
    CHECK(serialized.size() == 2);
}

TEST_CASE("v1 serialization - message payload 100MiB", "[serialization]") {
    oxenss::user_pubkey pub_key;
    REQUIRE(pub_key.load("054368520005786b249bcd461d28f75e560ea794014eeb17fcf6003f37d876783e"s));

    const std::chrono::system_clock::time_point timestamp{1'622'576'077s};
    oxenss::message base_msg{
            pub_key,
            "hash",
            oxenss::namespace_id::Default,
            timestamp,
            timestamp + 24h,
            std::string(1 * 1024 * 1024 /*1MiB*/, 'x')};
    std::vector<oxenss::message> msg_list(100, base_msg);  // 100 MiB total

    auto begin = std::chrono::high_resolution_clock::now();
    auto serialized =
            serialize_messages(msg_list.begin(), msg_list.end(), SERIALIZATION_VERSION_BT);
    auto elapsed = std::chrono::high_resolution_clock::now() - begin;

    size_t total_bytes = msg_list.size() * base_msg.data.size();
    std::string total_bytes_str = oxenss::util::get_human_readable_bytes(total_bytes);
    double total_gbs = static_cast<double>(total_bytes) / (1024 * 1024 * 1024);
    double gbs_per_s =
            total_gbs / std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

    fmt::println(
            "Messages: {}; Size: {}; Elapsed: {}; Rate: {:.2f} GiB/s",
            msg_list.size(),
            oxenss::util::get_human_readable_bytes(total_bytes),
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed),
            gbs_per_s);
}
