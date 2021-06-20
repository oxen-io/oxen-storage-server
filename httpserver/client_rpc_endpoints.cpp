#include "client_rpc_endpoints.h"
#include "oxen_logger.h"
#include "string_utils.hpp"
#include "time.hpp"

#include <chrono>
#include <type_traits>
#include <unordered_set>

#include <oxenmq/base64.h>
#include <oxenmq/hex.h>

namespace oxen::rpc {

using nlohmann::json;
using std::chrono::system_clock;
using oxenmq::bt_dict;
using oxenmq::bt_dict_consumer;
using oxenmq::bt_list;
using oxenmq::bt_value;

namespace {

template <typename T>
constexpr std::string_view type_desc =
    std::is_same_v<T, bool> ? "boolean"sv :
    std::is_unsigned_v<T> ? "positive integer"sv :
    std::is_integral_v<T> ? "integer"sv :
    std::is_same_v<T, system_clock::time_point> ? "integer timestamp (in milliseconds)"sv :
    std::is_same_v<T, std::vector<std::string>> ? "string array"sv :
    "string"sv;

// Extracts a field suitable for a `T` value from the given json with name `name`.  Takes the json
// params and the name.  Throws if it encounters an invalid value (i.e. expecting a number but given
// a bool).  Returns nullopt if the field isn't present or is present and set to null.
template <typename T>
std::optional<T> parse_field(const json& params, const char* name) {
    constexpr bool is_timestamp = std::is_same_v<T, system_clock::time_point>;
    constexpr bool is_str_array = std::is_same_v<T, std::vector<std::string>>;
    static_assert(std::is_unsigned_v<T> || std::is_integral_v<T> || is_timestamp || is_str_array ||
            std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>);
    auto it = params.find(name);
    if (it == params.end() || it->is_null())
        return std::nullopt;

    bool right_type =
        std::is_same_v<T, bool> ? it->is_boolean() :
        std::is_unsigned_v<T> || is_timestamp ? it->is_number_unsigned() :
        std::is_integral_v<T> ? it->is_number_integer() :
        is_str_array ? it->is_array() :
        it->is_string();
    if (is_str_array && right_type)
        for (auto& x : *it)
            if (!x.is_string())
                right_type = false;
    if (!right_type)
        throw parse_error{fmt::format(
                "Invalid value given for '{}': expected {}", name, type_desc<T>)};
    if constexpr (std::is_same_v<T, std::string_view>)
        return it->template get_ref<const std::string&>();
    else if constexpr (is_timestamp) {
        auto time = from_epoch_ms(it->template get<int64_t>());
        // If we get a small timestamp value (less than 1M seconds since epoch) then this was very
        // likely given as unix epoch seconds rather than milliseconds
        if (time.time_since_epoch() < 1'000'000s)
            throw parse_error{fmt::format(
                    "Invalid timestamp for '{}': timestamp must be in milliseconds", name)};
        return time;
    } else
        return it->template get<T>();
}

// Equivalent to the above, but for a bt_dict_consumer.  Note that this advances the current state
// of the bt_dict_consumer to just after the given field and so this *must* be called in sorted key
// order.
template <typename T>
std::optional<T> parse_field(bt_dict_consumer& params, const char* name) {
    constexpr bool is_timestamp = std::is_same_v<T, system_clock::time_point>;
    constexpr bool is_str_array = std::is_same_v<T, std::vector<std::string>>;
    static_assert(std::is_unsigned_v<T> || std::is_integral_v<T> || is_timestamp || is_str_array ||
            std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>);
    if (!params.skip_until(name))
        return std::nullopt;

    try {
        if constexpr (std::is_same_v<T, std::string_view>)
            return params.consume_string_view();
        else if constexpr (std::is_same_v<T, std::string>)
            return params.consume_string();
        else if constexpr (std::is_integral_v<T>)
            return params.consume_integer<T>();
        else if constexpr (is_timestamp)
            return from_epoch_ms(params.consume_integer<int64_t>());
        else if constexpr (is_str_array) {
            auto strs = std::make_optional<T>();
            for (auto l = params.consume_list_consumer(); !l.is_finished(); )
                strs->push_back(l.consume_string());
            return strs;
        }
    }
    catch (...) {}
    throw parse_error{fmt::format(
            "Invalid value given for '{}': expected {}", name, type_desc<T>)};
}

// Backwards compat code for fields like ttl and timestamp that are accepted either as integer *or*
// stringified integer.
template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
std::optional<T> parse_stringified(const json& params, const char* name) {
    if (auto it = params.find(name); it != params.end() && it->is_string()) {
        if (T value; util::parse_int(it->get_ref<const std::string&>(), value))
            return value;
        else
            throw parse_error{fmt::format("Invalid value given for '{}': {}", name, it->dump())};
    }
    return parse_field<T>(params, name);
}

#ifndef NDEBUG
constexpr bool check_ascending(std::string_view) { return true; }
template <typename... Args>
constexpr bool check_ascending(std::string_view a, std::string_view b, Args&&... args) {
    return a < b && check_ascending(b, std::forward<Args>(args)...);
}
#endif

// Loads fields from a bt_dict_consumer or a json object.  Names must be specified in alphabetical
// order.  Throws a parse_error if the field exists but cannot be converted into a `T`.
template <typename... T, typename Dict, typename... Names, typename = std::enable_if_t<
        sizeof...(T) == sizeof...(Names) && (std::is_convertible_v<Names, std::string_view> && ...)>>
std::tuple<std::optional<T>...> load_fields(Dict& params, const Names&... names) {
    assert(check_ascending(names...));
    return {parse_field<T>(params, names)...};
}

template <typename T>
void require(std::string_view name, const std::optional<T>& v) {
    if (!v)
        throw parse_error{fmt::format("Required field '{}' missing", name)};
}

template <typename T1, typename T2>
void require_at_most_one_of(std::string_view first, const std::optional<T1>& a, std::string_view second, const std::optional<T2>& b) {
    if (a && b)
        throw parse_error{fmt::format("Cannot specify both '{}' and '{}'", first, second)};
}


template <typename T1, typename T2>
void require_exactly_one_of(std::string_view first, const std::optional<T1>& a, std::string_view second, const std::optional<T2>& b, bool alias = false) {
    require_at_most_one_of(first, a, second, b);
    if (!(a || b))
        throw parse_error{fmt::format(
                alias ? "Required field '{}' missing" : "Required field '{}' or '{}' missing",
                first, second)};
}

template <typename RPC, typename Dict>
static void load_pk_signature(
        RPC &rpc,
        const Dict&,
        std::optional<std::string> pk,
        std::optional<std::string_view> sig) {
    require("pubkey", pk);
    require("signature", sig);
    if (!rpc.pubkey.load(std::move(*pk)))
        throw parse_error{fmt::format("Pubkey must be {} hex digits ({} bytes) long",
                USER_PUBKEY_SIZE_HEX, USER_PUBKEY_SIZE_BYTES)};

    if constexpr (std::is_same_v<json, Dict>) {
        if (!oxenmq::is_base64(*sig) || !(sig->size() == 88 || (sig->size() == 86 && sig->substr(84) == "==")))
            throw parse_error{"invalid signature: expected base64 encoded Ed25519 signature"};
        oxenmq::from_base64(sig->begin(), sig->end(), rpc.signature.begin());
    } else {
        if (sig->size() != 64)
            throw parse_error{"invalid signature: expected 64-byte Ed25519 signature"};
        std::memcpy(rpc.signature.data(), sig->data(), 64);
    }
    // NB: We don't validate the signature here, we only parse input
}


} // anon. namespace


template <typename Dict>
static void load(store& s, Dict& d) {
    auto [data, expiry, pubkey_alt, pubkey] =
        load_fields<std::string_view, system_clock::time_point, std::string, std::string>(
                d, "data", "expiry", "pubKey", "pubkey");

    // timestamp and ttl are special snowflakes: for backwards compat reasons, they can be passed as
    // strings when loading from json.
    std::optional<uint64_t> ttl;
    std::optional<system_clock::time_point> timestamp;
    if constexpr (std::is_same_v<Dict, json>) {
        if (auto ts = parse_stringified<int64_t>(d, "timestamp"))
            timestamp = from_epoch_ms(*ts);
        ttl = parse_stringified<uint64_t>(d, "ttl");
    } else {
        timestamp = parse_field<system_clock::time_point>(d, "timestamp");
        ttl = parse_field<uint64_t>(d, "ttl");
    }

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubkey_alt, true);
    if (!s.pubkey.load(std::move(pubkey ? *pubkey : *pubkey_alt)))
        throw parse_error{fmt::format("Pubkey must be {} hex digits/{} bytes long",
                USER_PUBKEY_SIZE_HEX, USER_PUBKEY_SIZE_BYTES)};

    require("timestamp", timestamp);
    require_exactly_one_of("expiry", expiry, "ttl", ttl);
    s.timestamp = *timestamp;
    s.expiry = expiry ? *expiry : s.timestamp + std::chrono::milliseconds{*ttl};

    require("data", data);
    if constexpr (std::is_same_v<Dict, json>) {
        // For json we require data be base64 encoded
        if (!oxenmq::is_base64(*data))
            throw parse_error{"Invalid 'data' value: not base64 encoded"};
        static_assert(store::MAX_MESSAGE_BODY % 3 == 0,
                "MAX_MESSAGE_BODY should be divisible by 3 so that max base64 encoded size avoids padding");
        if (data->size() > store::MAX_MESSAGE_BODY / 3 * 4)
            throw parse_error{fmt::format("Message body exceeds maximum allowed length of {} bytes",
                    store::MAX_MESSAGE_BODY)};
        s.data = oxenmq::from_base64(*data);
    } else {
        // Otherwise (i.e. bencoded) then we take data as bytes
        if (data->size() > store::MAX_MESSAGE_BODY)
            throw parse_error{fmt::format("Message body exceeds maximum allowed length of {} bytes",
                    store::MAX_MESSAGE_BODY)};
        s.data = *data;
    }
}
void store::load_from(json params) { load(*this, params); }
void store::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value store::to_bt() const {
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"timestamp", to_epoch_ms(timestamp)},
        {"expiry", to_epoch_ms(expiry)},
        {"data", std::string_view{data}}
    };
}

template <typename Dict>
static void load(retrieve& r, Dict& d) {
    auto [lastHash, last_hash, pubKey, pubkey] =
        load_fields<std::string, std::string, std::string, std::string>(
                d, "lastHash", "last_hash", "pubKey", "pubkey");

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubKey, true);
    if (!r.pubkey.load(std::move(pubkey ? *pubkey : *pubKey)))
        throw parse_error{fmt::format("Pubkey must be {} hex digits/{} bytes long",
                USER_PUBKEY_SIZE_HEX, USER_PUBKEY_SIZE_BYTES)};

    require_at_most_one_of("last_hash", last_hash, "lastHash", lastHash);
    if (lastHash)
        last_hash = std::move(lastHash);
    if (last_hash) {
        if (last_hash->empty()) // Treat empty string as not provided
            last_hash.reset();
        else if (last_hash->size() == 43) {
            if (!oxenmq::is_base64(*last_hash))
                throw parse_error{"Invalid last_hash: not base64"};
        }
        // TODO: Old hash format, can remove 14+ days after 2.2.0 upgrade takes effect
        else if (last_hash->size() == 128) {
            if (!oxenmq::is_hex(*last_hash))
                throw parse_error{"Invalid last_hash: not hex"};
        }
        else
            throw parse_error{"Invalid last_hash: expected base64 (43 chars) or hex (128 chars)"};
    }
    r.last_hash = std::move(last_hash);
}
void retrieve::load_from(json params) { load(*this, params); }
void retrieve::load_from(bt_dict_consumer params) { load(*this, params); }

static bool is_valid_message_hash(std::string_view hash) {
    return
        (hash.size() == 43 && oxenmq::is_base64(hash))
        ||
        // TODO: remove this in the future, once everything has been upgraded to a SS
        // that uses 43-byte base64 string hashes instead.
        (hash.size() == 128 && oxenmq::is_hex(hash));
}

template <typename Dict>
static void load(delete_msgs& dm, Dict& d) {
    auto [messages, pubkey, signature] =
        load_fields<std::vector<std::string>, std::string, std::string_view>(
            d, "messages", "pubkey", "signature");

    load_pk_signature(dm, d, pubkey, signature);
    require("messages", messages);
    dm.messages = std::move(*messages);
    if (dm.messages.empty())
        throw parse_error{"messages does not contain any message hashes"};
    for (const auto& m : dm.messages)
        if (!is_valid_message_hash(m))
            throw parse_error{"invalid message hash: " + m};
}
void delete_msgs::load_from(json params) { load(*this, params); }
void delete_msgs::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value delete_msgs::to_bt() const {
    bt_list msgs;
    for (auto& m : messages)
        msgs.emplace_back(std::string_view{m});
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"messages", std::move(msgs)},
        {"signature", util::view_guts(signature)},
    };
}


template <typename Dict>
static void load(delete_all& da, Dict& d) {
    auto [pubkey, signature, timestamp] =
        load_fields<std::string, std::string_view, system_clock::time_point>(
            d, "pubkey", "signature", "timestamp");

    load_pk_signature(da, d, pubkey, signature);
    require("timestamp", timestamp);
    da.timestamp = std::move(*timestamp);
}
void delete_all::load_from(json params) { load(*this, params); }
void delete_all::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value delete_all::to_bt() const {
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"signature", util::view_guts(signature)},
        {"timestamp", to_epoch_ms(timestamp)}
    };
}

template <typename Dict>
static void load(delete_before& db, Dict& d) {
    auto [before, pubkey, signature] =
        load_fields<system_clock::time_point, std::string, std::string_view>(
            d, "before", "pubkey", "signature");

    load_pk_signature(db, d, pubkey, signature);
    require("before", before);
    db.before = std::move(*before);
}
void delete_before::load_from(json params) { load(*this, params); }
void delete_before::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value delete_before::to_bt() const {
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"signature", util::view_guts(signature)},
        {"before", to_epoch_ms(before)}
    };
}

template <typename Dict>
static void load(expire_all& e, Dict& d) {
    auto [expiry, pubkey, signature] =
        load_fields<system_clock::time_point, std::string, std::string_view>(
            d, "expiry", "pubkey", "signature");

    load_pk_signature(e, d, pubkey, signature);
    require("expiry", expiry);
    e.expiry = std::move(*expiry);
}
void expire_all::load_from(json params) { load(*this, params); }
void expire_all::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value expire_all::to_bt() const {
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"signature", util::view_guts(signature)},
        {"expiry", to_epoch_ms(expiry)}
    };
}

template <typename Dict>
static void load(expire_msgs& e, Dict& d) {
    auto [expiry, messages, pubkey, signature] =
        load_fields<system_clock::time_point, std::vector<std::string>, std::string, std::string_view>(
            d, "expiry", "messages", "pubkey", "signature");

    load_pk_signature(e, d, pubkey, signature);
    require("expiry", expiry);
    e.expiry = std::move(*expiry);
    require("messages", messages);
    e.messages = std::move(*messages);
    if (e.messages.empty())
        throw parse_error{"messages does not contain any message hashes"};
    for (const auto& m : e.messages)
        if (!is_valid_message_hash(m))
            throw parse_error{"invalid message hash: " + m};
}
void expire_msgs::load_from(json params) { load(*this, params); }
void expire_msgs::load_from(bt_dict_consumer params) { load(*this, params); }
bt_value expire_msgs::to_bt() const {
    bt_list msgs;
    for (const auto& m : messages)
        msgs.emplace_back(std::string_view{m});
    return bt_dict{
        {"pubkey", pubkey.prefixed_raw()},
        {"signature", util::view_guts(signature)},
        {"expiry", to_epoch_ms(expiry)},
        {"messages", std::move(msgs)},
    };
}

template <typename Dict>
static void load(get_swarm& g, Dict& d) {
    auto [pubKey, pubkey] = load_fields<std::string, std::string>(d, "pubKey", "pubkey");

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubKey, true);
    if (!g.pubkey.load(std::move(pubkey ? *pubkey : *pubKey)))
        throw parse_error{fmt::format("Pubkey must be {} hex digits/{} bytes long",
                USER_PUBKEY_SIZE_HEX, USER_PUBKEY_SIZE_BYTES)};
}
void get_swarm::load_from(json params) { load(*this, params); }
void get_swarm::load_from(bt_dict_consumer params) { load(*this, params); }

inline const static std::unordered_set<std::string_view> allowed_oxend_endpoints{{
    "get_service_nodes"sv, "ons_resolve"sv}};

template <typename Dict>
static void load(oxend_request& o, Dict& d) {
    auto endpoint = parse_field<std::string>(d, "endpoint");
    require("endpoint", endpoint);
    o.endpoint = *endpoint;
    if (!allowed_oxend_endpoints.count(o.endpoint))
        throw parse_error{fmt::format("Invalid oxend endpoint '{}'", o.endpoint)};

    if constexpr (std::is_same_v<Dict, json>) {
        if (auto it = d.find("params"); it != d.end() && !it->is_null())
            o.params = *it;
    } else {
        if (auto json_str = parse_field<std::string_view>(d, "params")) {
            json params = json::parse(*json_str, nullptr, false);
            if (params.is_discarded())
                throw parse_error{"oxend_request params field does not contain valid json"};
            if (!params.is_null())
                o.params = std::move(params);
        }
    }
}
void oxend_request::load_from(json params) { load(*this, params); }
void oxend_request::load_from(bt_dict_consumer params) { load(*this, params); }

} // namespace oxen::rpc
