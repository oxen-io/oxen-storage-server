#include "serialization.h"

#include "oxen_logger.h"
#include "oxenmq/bt_serialize.h"
#include "service_node.h"
#include "time.hpp"
#include "string_utils.hpp"

#include <boost/endian/conversion.hpp>
#include <oxenmq/base64.h>

#include <chrono>

namespace oxen {

namespace v0 {
// Old serialization format; TODO: can go once everyone has updated to 2.2.0+
namespace {

template <typename T>
void serialize_integer(std::string& buf, T a) {
    boost::endian::native_to_little_inplace(a);
    buf += util::view_guts(a);
}

void serialize(std::string& buf, const std::string& str) {
    serialize_integer<uint64_t>(buf, str.size());
    buf += str;
}

void serialize_message(std::string& res, const message_t& msg) {

    res += msg.pubkey.prefixed_hex();
    serialize(res, msg.hash);
    serialize(res, oxenmq::to_base64(msg.data));
    // For backwards compat, we send expiry as a ttl
    serialize_integer(res, to_epoch_ms(msg.expiry) - to_epoch_ms(msg.timestamp));
    serialize_integer(res, to_epoch_ms(msg.timestamp));
    serialize(res, ""s); // Empty nonce string, no longer used, but serialization currently requires it be here

    OXEN_LOG(trace, "serialized message: {}", msg.data);
}

template <typename T>
std::optional<T> deserialize_integer(std::string_view& slice) {
    static_assert(std::is_trivial_v<T>);
    T val;
    std::memcpy(reinterpret_cast<char*>(&val), slice.data(), sizeof(T));
    slice.remove_prefix(sizeof(T));
    boost::endian::native_to_little_inplace(val);
    return val;
}


std::optional<std::string> deserialize_string(std::string_view& slice, size_t len) {

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

std::vector<message_t> deserialize_messages_old(std::string_view slice) {
    std::vector<message_t> result;

    while (!slice.empty()) {
        auto& item = result.emplace_back();

        /// Deserialize PK
        size_t pksize = USER_PUBKEY_SIZE_HEX;
        if (!is_mainnet)
            pksize -= 2;
        if (auto pk = deserialize_string(slice, pksize);
                !(pk && item.pubkey.load(std::move(*pk)))) {
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
        if (auto data = deserialize_string(slice);
                data && oxenmq::is_base64(*data))
            item.data = oxenmq::from_base64(*data);
        else {
            OXEN_LOG(debug, "Could not deserialize data");
            return {};
        }

        /// Deserialize TTL
        std::chrono::milliseconds ttl;
        if (auto ttl_ms = deserialize_integer<int64_t>(slice))
            ttl = std::chrono::milliseconds{*ttl_ms};
        else {
            OXEN_LOG(debug, "Could not deserialize ttl");
            return {};
        }

        /// Deserialize Timestamp
        if (auto timestamp = deserialize_integer<int64_t>(slice))
            item.timestamp = from_epoch_ms(*timestamp);
        else {
            OXEN_LOG(debug, "Could not deserialize timestamp");
            return {};
        }

        item.expiry = item.timestamp + ttl;

        /// Deserialize Nonce
        /// TODO: Nonce is unused but we have to call this for backwards compat (and if we don't
        /// pull it off the string we can't read the next element).  It would be good to complete
        /// replace this completely rigid and undocumented protocol with something extensible that
        /// also doesn't do dumb things like not having records, sending a Session internal prefix,
        /// using binary 8-byte string lengths (sometimes, but other times not), sending binary
        /// values as hex, and using a rigid fixed ordering of fields.
        [[maybe_unused]] auto unused_nonce = deserialize_string(slice);

        OXEN_LOG(trace, "pk: {}, msg: {}", item.pubkey.prefixed_hex(), oxenmq::to_base64(item.data));
    }

    OXEN_LOG(trace, "=== END ===");

    return result;
}

}
}

std::vector<std::string> serialize_messages(std::function<const message_t*()> next_msg, uint8_t version) {

    std::vector<std::string> res;

    if (version == 0) {
        res.emplace_back();
        while (auto* msg = next_msg()) {
            if (res.back().size() > SERIALIZATION_BATCH_SIZE)
                res.emplace_back();
            v0::serialize_message(res.back(), *msg);
        }
    } else {
        oxenmq::bt_list l;
        size_t counter = 2;
        while (auto* msg = next_msg()) {
            size_t ser_size =
                1 + // version byte
                2 + // l...e
                36 + // 33:pubkey
                2*15 + // millisecond epochs (13 digits) + `i...e`
                (4 + msg->hash.size()) + // xxx:HASH
                (6 + msg->data.size()) // xxxxx:DATA
            ;
            counter += ser_size;
            if (!l.empty() && counter > SERIALIZATION_BATCH_SIZE) {
                // Adding this message would push us over the limit, so finish it off and start a
                // new serialization piece.
                std::ostringstream oss;
                oss << uint8_t{1} /*version*/ << oxenmq::bt_serializer(l);
                res.push_back(oss.str());
                l.clear();
                counter = 1 + 2 + ser_size;
            }
            assert(msg->pubkey);
            l.push_back(oxenmq::bt_list{{
                msg->pubkey.prefixed_raw(),
                msg->hash,
                to_epoch_ms(msg->timestamp),
                to_epoch_ms(msg->expiry),
                msg->data}});
        }

        std::ostringstream oss;
        oss << uint8_t{1} /* version*/ << oxenmq::bt_serializer(l);
        res.push_back(oss.str());
    }

    return res;
}



std::vector<message_t> deserialize_messages(std::string_view slice) {

    OXEN_LOG(trace, "=== Deserializing ===");

    // v0 didn't send a version at all, and sent things incredibly inefficiently.
    // v1+ put the version as the first byte (but can't use any of '0'..'9','a'..'f','A'..'F'
    // because v0 starts out with a hex pubkey).
    uint8_t version = 0;
    if (!slice.empty() && slice.front() < '0' && slice.front() != 0) {
        version = slice.front();
        slice.remove_prefix(1);
    }

    if (version == 0)
        return v0::deserialize_messages_old(slice);

    // v1:
    std::vector<message_t> result;
    try {
        oxenmq::bt_list_consumer l{slice};
        while (!l.is_finished()) {
            auto& item = result.emplace_back();
            auto m = l.consume_list_consumer();
            if (!item.pubkey.load(m.consume_string_view())) {
                OXEN_LOG(debug, "Unable to deserialize(v1) pubkey");
                return {};
            }
            item.hash = m.consume_string();
            item.timestamp = from_epoch_ms(m.consume_integer<int64_t>());
            item.expiry = from_epoch_ms(m.consume_integer<int64_t>());
            item.data = m.consume_string();
        }
    } catch (const std::exception& e) {
        throw e;
        OXEN_LOG(debug, "Failed to deserialize(v1): {}", e.what());
        return {};
    }

    OXEN_LOG(trace, "=== END ===");

    return result;
}

} // namespace oxen
