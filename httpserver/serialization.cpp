#include "serialization.h"

/// TODO: should only be aware of messages
#include "Item.hpp"
#include "oxen_logger.h"
#include "service_node.h"
#include "string_utils.hpp"

#include <boost/endian/conversion.hpp>

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

template <typename T>
void serialize_message(std::string& res, const T& msg) {

    /// TODO: use binary / base64 representation for pk
    res += msg.pub_key;
    serialize(res, msg.hash);
    serialize(res, msg.data);
    serialize_integer(res, msg.ttl);
    serialize_integer(res, msg.timestamp);
    serialize(res, msg.nonce);

    OXEN_LOG(trace, "serialized message: {}", msg.data);
}

template void serialize_message(std::string& res, const message_t& msg);
template void serialize_message(std::string& res, const Item& msg);

template <typename T>
std::vector<std::string> serialize_messages(const std::vector<T>& msgs) {

    std::vector<std::string> res;

    std::string buf;

    constexpr size_t BATCH_SIZE = 500000;

    for (const auto& msg : msgs) {
        serialize_message(buf, msg);
        if (buf.size() > BATCH_SIZE) {
            res.push_back(std::move(buf));
            buf.clear();
        }
    }

    if (!buf.empty()) {
        res.push_back(std::move(buf));
    }

    return res;
}

template std::vector<std::string>
serialize_messages(const std::vector<message_t>& msgs);

template std::vector<std::string>
serialize_messages(const std::vector<Item>& msgs);

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

std::vector<message_t> deserialize_messages(std::string_view slice) {

    OXEN_LOG(trace, "=== Deserializing ===");

    std::vector<message_t> result;

    while (!slice.empty()) {

        /// Deserialize PK
        auto pk = deserialize_string(slice, oxen::get_user_pubkey_size());
        if (!pk) {
            OXEN_LOG(debug, "Could not deserialize pk");
            return {};
        }

        /// Deserialize Hash
        auto hash = deserialize_string(slice);
        if (!hash) {
            OXEN_LOG(debug, "Could not deserialize hash");
            return {};
        }

        /// Deserialize Data
        auto data = deserialize_string(slice);
        if (!data) {
            OXEN_LOG(debug, "Could not deserialize data");
            return {};
        }

        /// Deserialize TTL
        auto ttl = deserialize_integer<uint64_t>(slice);
        if (!ttl) {
            OXEN_LOG(debug, "Could not deserialize ttl");
            return {};
        }

        /// Deserialize Timestamp
        auto timestamp = deserialize_integer<uint64_t>(slice);
        if (!timestamp) {
            OXEN_LOG(debug, "Could not deserialize timestamp");
            return {};
        }

        /// Deserialize Nonce
        /// TODO: Nonce is unused but we have to call this for backwards compat (and if we don't
        /// pull it off the string we can't read the next element).  It would be good to complete
        /// replace this completely rigid and undocumented protocol with something extensible that
        /// also doesn't do dumb things like not having records, sending a Session internal prefix,
        /// using binary 8-byte string lengths (sometimes, but other times not), sending binary
        /// values as hex, and using a rigid fixed ordering of fields.
        [[maybe_unused]] auto unused_nonce = deserialize_string(slice);

        OXEN_LOG(trace, "Deserialized data: {}", *data);

        OXEN_LOG(trace, "pk: {}, msg: {}", *pk, *data);

        result.emplace_back(std::move(*pk), std::move(*data), std::move(*hash), *ttl, *timestamp);
    }

    OXEN_LOG(trace, "=== END ===");

    return result;
}

} // namespace oxen
