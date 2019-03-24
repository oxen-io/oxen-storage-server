#include "serialization.h"

/// TODO: should only be aware of messages
#include "Item.hpp"
#include "service_node.h"

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

using service_node::storage::Item;

namespace loki {

using iter_t = const char*;

static uint32_t deserialize_uint32(std::string::const_iterator& it) {

    auto b1 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b2 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b3 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b4 = static_cast<uint32_t>(reinterpret_cast<const uint8_t&>(*it++));

    return static_cast<uint32_t>(b1 << 24 | b2 << 16 | b3 << 8 | b4);
}

static uint64_t deserialize_uint64(std::string::const_iterator& it) {

    auto b1 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b2 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b3 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b4 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));

    auto b5 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b6 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b7 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));
    auto b8 = static_cast<uint64_t>(reinterpret_cast<const uint8_t&>(*it++));

    return static_cast<uint64_t>(b1 << 56 | b2 << 48 | b3 << 40 | b4 << 32 |
                                 b5 << 24 | b6 << 16 | b7 << 8 | b8);
}

static void serialize_uint32(std::string& buf, uint32_t a) {

    char b0 = static_cast<char>(((a & 0xFF000000) >> 24));
    char b1 = static_cast<char>(((a & 0xFF0000) >> 16));
    char b2 = static_cast<char>(((a & 0xFF00) >> 8));
    char b3 = static_cast<char>(((a & 0xFF)));

    buf += b0;
    buf += b1;
    buf += b2;
    buf += b3;
}

static void serialize_uint64(std::string& buf, uint64_t a) {

    char b0 = static_cast<char>(((a & 0xFF00000000000000) >> 56));
    char b1 = static_cast<char>(((a & 0xFF000000000000) >> 48));
    char b2 = static_cast<char>(((a & 0xFF0000000000) >> 40));
    char b3 = static_cast<char>(((a & 0xFF00000000) >> 32));
    char b4 = static_cast<char>(((a & 0xFF000000) >> 24));
    char b5 = static_cast<char>(((a & 0xFF0000) >> 16));
    char b6 = static_cast<char>(((a & 0xFF00) >> 8));
    char b7 = static_cast<char>(((a & 0xFF)));

    buf += b0;
    buf += b1;
    buf += b2;
    buf += b3;
    buf += b4;
    buf += b5;
    buf += b6;
    buf += b7;
}

static void serialize(std::string& buf, const std::string& str) {

    buf.reserve(buf.size() + str.size() + 4);
    serialize_uint32(buf, str.size());
    buf += str;
}

std::string serialize_message(const message_t& msg) {

    std::string res;

    res += msg.pk_;
    serialize(res, msg.hash_);
    serialize(res, msg.text_);
    serialize_uint64(res, msg.ttl_);
    serialize_uint64(res, msg.timestamp_);
    serialize(res, msg.nonce_);

    BOOST_LOG_TRIVIAL(debug)
        << "serialized message: " << msg.text_ << std::endl;

    return res;
}

/// TODO: reuse the one above
std::string serialize_message(const Item& item) {

    std::string res;

    res += item.pubKey;
    serialize(res, item.hash);
    serialize(res, item.bytes);
    serialize_uint64(res, item.ttl);
    serialize_uint64(res, item.timestamp);
    serialize(res, item.nonce);

    BOOST_LOG_TRIVIAL(debug)
        << "serialized message: " << item.bytes << std::endl;

    return res;
}

struct string_view {

    std::string::const_iterator it;
    const std::string::const_iterator it_end;

    string_view(const std::string& data)
        : it(data.begin()), it_end(data.end()) {}

    size_t size() { return it_end - it; }

    bool empty() { return it_end <= it; }
};

static boost::optional<std::string> deserialize_string(string_view& slice,
                                                       size_t len) {

    if (slice.size() < len) {
        return boost::none;
    }

    std::string res = std::string(slice.it, slice.it + len);
    slice.it += len;

    return res;
}

static boost::optional<std::string> deserialize_string(string_view& slice) {

    if (slice.size() < 4)
        return boost::none;

    uint32_t len = deserialize_uint32(slice.it); // already increments `it`!

    if (slice.size() < len)
        return boost::none;

    std::string res = std::string(slice.it, slice.it + len);
    slice.it += len;

    return res;
}

static boost::optional<uint64_t> deserialize_uint64(string_view& slice) {

    if (slice.size() < 8)
        return boost::none;

    auto res = deserialize_uint64(slice.it);

    return res;
}

std::vector<message_t> deserialize_messages(const std::string& blob) {

    BOOST_LOG_TRIVIAL(trace) << "=== Deserializing ===";

    auto it = blob.begin();

    constexpr size_t PK_SIZE = 66; // characters in hex;

    std::vector<message_t> result;

    /// TODO: better incapsulate serialization/deserialization!
    string_view slice{blob};

    bool success = false;

    while (!slice.empty()) {

        /// Deserialize PK
        auto pk = deserialize_string(slice, PK_SIZE);
        if (!pk) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize pk";
            return {};
        }

        /// Deserialize Hash
        auto hash = deserialize_string(slice);
        if (!hash) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize hash";
            return {};
        }

        /// Deserialize Data
        auto data = deserialize_string(slice);
        if (!data) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize data";
            return {};
        }

        /// Deserialize TTL
        auto ttl = deserialize_uint64(slice);
        if (!ttl) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize ttl";
            return {};
        }

        /// Deserialize Timestamp
        auto timestamp = deserialize_uint64(slice);
        if (!timestamp) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize timestamp";
            return {};
        }

        /// Deserialize Nonce
        auto nonce = deserialize_string(slice);
        if (!nonce) {
            BOOST_LOG_TRIVIAL(error) << "could not deserialize nonce";
            return {};
        }

        BOOST_LOG_TRIVIAL(trace) << "deserialized data: " << *data << std::endl;

        BOOST_LOG_TRIVIAL(trace)
            << boost::format("pk: %1%, msg: %2%") % *pk % *data;

        // TODO: Actually use the message values here
        result.push_back({pk->c_str(), data->c_str(), hash->c_str(), *ttl,
                          *timestamp, nonce->c_str()});
    }

    BOOST_LOG_TRIVIAL(trace) << "=== END ===";

    return result;
}

} // namespace loki
