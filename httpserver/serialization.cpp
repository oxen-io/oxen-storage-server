#include "serialization.h"

/// TODO: should only be aware of messages
#include "Item.hpp"
#include "oxen_logger.h"
#include "service_node.h"
#include "string_utils.hpp"

#include <boost/endian/conversion.hpp>
#include <chrono>

namespace oxen {

using storage::Item;

template <typename T>
static void serialize_integer(std::string& buf, T a) {
    boost::endian::native_to_little_inplace(a);
    buf += util::view_guts(a);
}

static void serialize(std::string& buf, const std::string& str) {
    serialize_integer<uint64_t>(buf, str.size());
    buf += str;
}

void serialize_message(std::string& res, const storage::Item& msg) {

    /// TODO: use binary / base64 representation for pk
    res += msg.pub_key;
    serialize(res, msg.hash);
    serialize(res, msg.data);
    // For backwards compat, we send expiry as a ttl
    serialize_integer<uint64_t>(res, std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.expiration - msg.timestamp).count());
    serialize_integer<uint64_t>(res, std::chrono::duration_cast<std::chrono::milliseconds>(
                msg.timestamp.time_since_epoch()).count());
    serialize(res, ""s); // Empty nonce string, no longer used, but serialization currently requires it be here

    OXEN_LOG(trace, "serialized message: {}", msg.data);
}

std::vector<std::string> serialize_messages(const std::vector<storage::Item>& msgs) {

    std::vector<std::string> res;
    res.emplace_back();

    for (const auto& msg : msgs) {
        if (res.back().size() > SERIALIZATION_BATCH_SIZE)
            res.emplace_back();
        serialize_message(res.back(), msg);
    }

    return res;
}

template <typename T>
static std::optional<T> deserialize_integer(std::string_view& slice) {
    static_assert(std::is_trivial_v<T>);
    T val;
    std::memcpy(reinterpret_cast<char*>(&val), slice.data(), sizeof(T));
    slice.remove_prefix(sizeof(T));
    boost::endian::native_to_little_inplace(val);
    return val;
}


static std::optional<std::string> deserialize_string(std::string_view& slice,
                                                     size_t len) {

    if (slice.size() < len) {
        return std::nullopt;
    }

    std::string res{slice.substr(0, len)};
    slice.remove_prefix(len);
    return std::move(res);
}

static std::optional<std::string> deserialize_string(std::string_view& slice) {
    // A uint64_t is stupidly large for a string length, but we can't change it without breaking the
    // protocol.
    if (auto len = deserialize_integer<uint64_t>(slice))
        return deserialize_string(slice, *len);
    return std::nullopt;
}

std::vector<storage::Item> deserialize_messages(std::string_view slice) {

    OXEN_LOG(trace, "=== Deserializing ===");

    std::vector<storage::Item> result;

    while (!slice.empty()) {
        auto& item = result.emplace_back();

        /// Deserialize PK
        if (auto pk = deserialize_string(slice, oxen::get_user_pubkey_size()))
            item.pub_key = std::move(*pk);
        else {
            OXEN_LOG(debug, "Could not deserialize pk");
            return {};
        }

        /// Deserialize Hash
        if (auto hash = deserialize_string(slice))
            item.hash = std::move(*hash);
        else {
            OXEN_LOG(debug, "Could not deserialize hash");
            return {};
        }

        /// Deserialize Data
        if (auto data = deserialize_string(slice))
            item.data = std::move(*data);
        else {
            OXEN_LOG(debug, "Could not deserialize data");
            return {};
        }

        /// Deserialize TTL
        std::chrono::milliseconds ttl;
        if (auto ttl_ms = deserialize_integer<uint64_t>(slice))
            ttl = std::chrono::milliseconds{*ttl_ms};
        else {
            OXEN_LOG(debug, "Could not deserialize ttl");
            return {};
        }

        /// Deserialize Timestamp
        if (auto timestamp = deserialize_integer<uint64_t>(slice))
            item.timestamp = std::chrono::system_clock::time_point{std::chrono::milliseconds{*timestamp}};
        else {
            OXEN_LOG(debug, "Could not deserialize timestamp");
            return {};
        }

        item.expiration = item.timestamp + ttl;

        /// Deserialize Nonce
        /// TODO: Nonce is unused but we have to call this for backwards compat (and if we don't
        /// pull it off the string we can't read the next element).  It would be good to complete
        /// replace this completely rigid and undocumented protocol with something extensible that
        /// also doesn't do dumb things like not having records, sending a Session internal prefix,
        /// using binary 8-byte string lengths (sometimes, but other times not), sending binary
        /// values as hex, and using a rigid fixed ordering of fields.
        [[maybe_unused]] auto unused_nonce = deserialize_string(slice);

        OXEN_LOG(trace, "pk: {}, msg: {}", item.pub_key, item.data);
    }

    OXEN_LOG(trace, "=== END ===");

    return result;
}

} // namespace oxen
