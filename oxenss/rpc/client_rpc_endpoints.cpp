#include "client_rpc_endpoints.h"
#include "request_handler.h"
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/time.hpp>
#include <oxenss/version.h>

#include <chrono>
#include <limits>
#include <type_traits>
#include <unordered_set>
#include <variant>

#include <oxenc/base64.h>
#include <oxenc/hex.h>

namespace oxenss::rpc {

using nlohmann::json;
using oxenc::bt_dict;
using oxenc::bt_dict_consumer;
using oxenc::bt_list;
using oxenc::bt_value;
using std::chrono::system_clock;

namespace {
    template <typename T>
    constexpr bool is_timestamp = std::is_same_v<T, system_clock::time_point>;
    template <typename T>
    constexpr bool is_str_array = std::is_same_v<T, std::vector<std::string>>;
    template <typename T>
    constexpr bool is_int_array = std::is_same_v<T, std::vector<int>>;
    template <typename T>
    constexpr bool is_namespace_var = std::is_same_v<T, namespace_var>;

    template <typename T>
    constexpr std::string_view type_desc = std::is_same_v<T, bool>         ? "boolean"sv
                                         : std::is_unsigned_v<T>           ? "positive integer"sv
                                         : std::is_integral_v<T>           ? "integer"sv
                                         : is_namespace_var<T>             ? "integer or \"all\""sv
                                         : std::is_same_v<T, namespace_id> ? "16-bit integer"sv
                                         : is_timestamp<T> ? "integer timestamp (in milliseconds)"sv
                                         : is_str_array<T> ? "string array"sv
                                         : is_int_array<T> ? "integer array"sv
                                                           : "string"sv;

    template <typename T>
    constexpr bool is_parseable_v =
            std::is_unsigned_v<T> || std::is_integral_v<T> || is_timestamp<T> || is_str_array<T> ||
            is_int_array<T> || is_namespace_var<T> || std::is_same_v<T, std::string_view> ||
            std::is_same_v<T, std::string> || std::is_same_v<T, namespace_id>;

    // Extracts a field suitable for a `T` value from the given json with name `name`.  Takes
    // the json params and the name.  Throws if it encounters an invalid value (i.e. expecting a
    // number but given a bool).  Returns nullopt if the field isn't present or is present and
    // set to null.
    template <typename T>
    std::optional<T> parse_field(const json& params, const char* name) {
        static_assert(is_parseable_v<T>);
        auto it = params.find(name);
        if (it == params.end() || it->is_null())
            return std::nullopt;

        bool right_type = std::is_same_v<T, bool>                  ? it->is_boolean()
                        : std::is_unsigned_v<T> || is_timestamp<T> ? it->is_number_unsigned()
                        : std::is_integral_v<T> || std::is_same_v<T, namespace_id>
                                ? it->is_number_integer()
                        : is_namespace_var<T> ? it->is_number_integer() || it->is_string()
                        : is_str_array<T> || is_int_array<T> ? it->is_array()
                                                             : it->is_string();
        if (is_str_array<T> && right_type) {
            for (auto& x : *it)
                if (!x.is_string())
                    right_type = false;
        } else if (is_int_array<T> && right_type) {
            for (auto& x : *it)
                if (!x.is_number_integer())
                    right_type = false;
        }

        if (!right_type)
            throw parse_error{
                    fmt::format("Invalid value given for '{}': expected {}", name, type_desc<T>)};
        if constexpr (std::is_same_v<T, std::string_view>)
            return it->template get_ref<const std::string&>();
        else if constexpr (is_timestamp<T>) {
            auto time = from_epoch_ms(it->template get<int64_t>());
            // If we get a small timestamp value (less than 1M seconds since epoch) then this
            // was very likely given as unix epoch seconds rather than milliseconds
            if (time.time_since_epoch() < 1'000'000s)
                throw parse_error{fmt::format(
                        "Invalid timestamp for '{}': timestamp must be in milliseconds", name)};
            return time;
        } else if constexpr (is_namespace_var<T> || std::is_same_v<T, namespace_id>) {
            if (it->is_number_integer()) {
                int64_t id = it->get<int64_t>();
                if (id < NAMESPACE_MIN || id > NAMESPACE_MAX)
                    throw parse_error{
                            fmt::format("Invalid value given for '{}': value out of range", name)};
                return namespace_id{static_cast<std::underlying_type_t<namespace_id>>(id)};
            }
            if constexpr (is_namespace_var<T>)
                if (it->is_string() && it->get_ref<const std::string&>() == "all")
                    return namespace_all;
            throw parse_error{
                    fmt::format("Invalid value given for '{}': expected integer or \"all\"", name)};
        } else {
            return it->template get<T>();
        }
    }

    // Equivalent to the above, but for a bt_dict_consumer.  Note that this advances the
    // current state of the bt_dict_consumer to just after the given field and so this
    // *must* be called in sorted key order.
    template <typename T>
    std::optional<T> parse_field(bt_dict_consumer& params, const char* name) {
        static_assert(is_parseable_v<T>);
        if (!params.skip_until(name))
            return std::nullopt;

        try {
            if constexpr (std::is_same_v<T, std::string_view>)
                return params.consume_string_view();
            else if constexpr (std::is_same_v<T, std::string>)
                return params.consume_string();
            else if constexpr (std::is_integral_v<T>)
                return params.consume_integer<T>();
            else if constexpr (is_timestamp<T>)
                return from_epoch_ms(params.consume_integer<int64_t>());
            else if constexpr (is_str_array<T> || is_int_array<T>) {
                auto elems = std::make_optional<T>();
                for (auto l = params.consume_list_consumer(); !l.is_finished();)
                    if constexpr (is_str_array<T>)
                        elems->push_back(l.consume_string());
                    else
                        elems->push_back(l.consume_integer<int>());
                return elems;
            } else if constexpr (is_namespace_var<T> || std::is_same_v<T, namespace_id>) {
                if (params.is_integer())
                    return namespace_id{
                            params.consume_integer<std::underlying_type_t<namespace_id>>()};
                if constexpr (is_namespace_var<T>)
                    if (params.is_string() && params.consume_string_view() == "all"sv)
                        return namespace_all;
            }
        } catch (...) {
        }
        throw parse_error{
                fmt::format("Invalid value given for '{}': expected {}", name, type_desc<T>)};
    }

    // Backwards compat code for fields like ttl and timestamp that are accepted either
    // as integer *or* stringified integer.
    template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    std::optional<T> parse_stringified(const json& params, const char* name) {
        if (auto it = params.find(name); it != params.end() && it->is_string()) {
            if (T value; util::parse_int(it->get_ref<const std::string&>(), value))
                return value;
            else
                throw parse_error{
                        fmt::format("Invalid value given for '{}': {}", name, it->dump())};
        }
        return parse_field<T>(params, name);
    }

#ifndef NDEBUG
    constexpr bool check_ascending(std::string_view) {
        return true;
    }
    template <typename... Args>
    constexpr bool check_ascending(std::string_view a, std::string_view b, Args&&... args) {
        return a < b && check_ascending(b, std::forward<Args>(args)...);
    }
#endif

    // Loads fields from a bt_dict_consumer or a json object.  Names must be specified
    // in alphabetical order.  Throws a parse_error if the field exists but cannot be
    // converted into a `T`.
    template <
            typename... T,
            typename Dict,
            typename... Names,
            typename = std::enable_if_t<
                    sizeof...(T) == sizeof...(Names) &&
                    (std::is_convertible_v<Names, std::string_view> && ...)>>
    std::tuple<std::optional<T>...> load_fields(Dict& params, const Names&... names) {
        assert(check_ascending(names...));
        return {parse_field<T>(params, names)...};
    }

    template <typename T>
    void require(std::string_view name, const std::optional<T>& v) {
        if (!v)
            throw parse_error{fmt::format("Required field '{}' missing", name)};
    }

    template <typename... T>
    void require(std::string_view name, const std::variant<std::monostate, T...>& v) {
        if (v.index() == 0)
            throw parse_error{fmt::format("Required field '{}' missing", name)};
    }

    template <typename T1, typename T2>
    void require_at_most_one_of(
            std::string_view first,
            const std::optional<T1>& a,
            std::string_view second,
            const std::optional<T2>& b) {
        if (a && b)
            throw parse_error{fmt::format("Cannot specify both '{}' and '{}'", first, second)};
    }

    template <typename T1, typename T2>
    void require_exactly_one_of(
            std::string_view first,
            const std::optional<T1>& a,
            std::string_view second,
            const std::optional<T2>& b,
            bool alias = false) {
        require_at_most_one_of(first, a, second, b);
        if (!(a || b))
            throw parse_error{fmt::format(
                    alias ? "Required field '{}' missing" : "Required field '{}' or '{}' missing",
                    first,
                    second)};
    }

    template <typename RPC>
    void load_pk(RPC& rpc, std::optional<std::string>& pk) {
        require("pubkey", pk);
        if (!rpc.pubkey.load(std::move(*pk)))
            throw parse_error{fmt::format(
                    "Pubkey must be {} hex digits ({} bytes) long",
                    USER_PUBKEY_SIZE_HEX,
                    USER_PUBKEY_SIZE_BYTES)};
    }

    template <typename T>
    constexpr bool is_std_optional = false;
    template <typename T>
    constexpr bool is_std_optional<std::optional<T>> = true;

    // Parses (but does not verify) a required request signature value.
    template <typename RPC, typename Dict>
    void load_pk_signature(
            RPC& rpc,
            const Dict&,
            std::optional<std::string>& pk,
            const std::optional<std::string_view>& pk_ed,
            const std::optional<std::string_view>& sig) {
        load_pk(rpc, pk);
        require("signature", sig);

        if (pk_ed) {
            if (rpc.pubkey.type() != 5)
                throw parse_error{"pubkey_ed25519 is only permitted for 05[...] pubkeys"};
            if (pk_ed->size() == 64) {
                if (!oxenc::is_hex(*pk_ed))
                    throw parse_error{"invalid pubkey_ed25519: value is not hex"};
                oxenc::from_hex(pk_ed->begin(), pk_ed->end(), rpc.pubkey_ed25519.emplace().begin());
            } else if (pk_ed->size() == 32) {
                std::memcpy(rpc.pubkey_ed25519.emplace().data(), pk_ed->data(), pk_ed->size());
            } else {
                throw parse_error{
                        "Invalid pubkey_ed25519: expected 64 hex char or 32 byte "
                        "pubkey"};
            }
        }

        unsigned char* sig_data_ptr;
        if constexpr (is_std_optional<decltype(rpc.signature)>)
            sig_data_ptr = rpc.signature.emplace().data();
        else
            sig_data_ptr = rpc.signature.data();

        if constexpr (std::is_same_v<json, Dict>) {
            if (!oxenc::is_base64(*sig) ||
                !(sig->size() == 86 || (sig->size() == 88 && sig->substr(86) == "==")))
                throw parse_error{"invalid signature: expected base64 encoded Ed25519 signature"};
            oxenc::from_base64(sig->begin(), sig->end(), sig_data_ptr);
        } else {
            if (sig->size() != 64)
                throw parse_error{"invalid signature: expected 64-byte Ed25519 signature"};
            std::memcpy(sig_data_ptr, sig->data(), 64);
        }
    }

    template <typename RPC, typename Dict>
    void load_subaccount(
            RPC& rpc,
            const Dict&,
            const std::optional<std::string_view>& subacc,
            const std::optional<std::string_view> subacc_sig) {
        if (!subacc || subacc->empty())
            return;
        if (!subacc_sig)
            throw parse_error{
                    "invalid subaccount: subaccount_sig is required when using subaccount"};
        const auto& sa = *subacc;
        const auto& sa_sig = *subacc_sig;
        auto& signed_subacc = rpc.subaccount.emplace();
        if constexpr (std::is_same_v<json, Dict>) {
            if (oxenc::is_base64(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 4 / 3)
                oxenc::from_base64(sa.begin(), sa.end(), signed_subacc.token.token.begin());
            else if (oxenc::is_hex(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 2)
                oxenc::from_hex(sa.begin(), sa.end(), signed_subacc.token.token.begin());
            else
                throw parse_error{
                        "invalid subaccount: expected base64 or hex-encoded subaccount token"};

            if (!oxenc::is_base64(sa_sig) ||
                !(sa_sig.size() == 86 || (sa_sig.size() == 88 && sa_sig.substr(86) == "==")))
                throw parse_error{
                        "invalid subaccount signature: expected base64 encoded Ed25519 signature"};
            oxenc::from_base64(sa_sig.begin(), sa_sig.end(), signed_subacc.signature.begin());
        } else {
            if (sa.size() != SUBACCOUNT_TOKEN_LENGTH)
                throw parse_error{"invalid subaccount token: invalid token length"};
            std::memcpy(signed_subacc.token.token.data(), sa.data(), SUBACCOUNT_TOKEN_LENGTH);
            if (sa_sig.size() != 64)
                throw parse_error{"invalid signature: expected 64-byte Ed25519 signature"};
            std::memcpy(signed_subacc.signature.data(), sa_sig.data(), 64);
        }
    }

    void set_variant(bt_dict& dict, const std::string& key, const namespace_var& ns) {
        if (auto* id = std::get_if<namespace_id>(&ns))
            dict[key] = static_cast<std::underlying_type_t<namespace_id>>(*id);
        else {
            assert(std::holds_alternative<namespace_all_t>(ns));
            dict[key] = "all";
        }
    }

    template <typename T, typename = void>
    inline constexpr bool has_subaccount = false;
    template <typename T>
    inline constexpr bool has_subaccount<T, std::void_t<decltype(T::subaccount)>> = true;
    template <typename T>
    inline constexpr bool is_optional = false;
    template <typename T>
    inline constexpr bool is_optional<std::optional<T>> = true;
    template <typename T>
    inline constexpr bool is_optional<const std::optional<T>&> = true;

    template <typename T>
    bt_dict to_bt_common(const T& req) {
        bt_dict d{
                {"pubkey", req.pubkey.prefixed_raw()},
        };
        if constexpr (is_optional<decltype(req.signature)>) {
            if (req.signature)
                d["signature"] = util::view_guts(*req.signature);
        } else {
            d["signature"] = util::view_guts(req.signature);
        }
        if constexpr (has_subaccount<T>) {
            if (req.subaccount) {
                d["subaccount"] = req.subaccount->token.sview();
                d["subaccount_sig"] = util::view_guts(req.subaccount->signature);
            }
        }
        if (req.pubkey_ed25519)
            d["pubkey_ed25519"] = std::string_view{
                    reinterpret_cast<const char*>(req.pubkey_ed25519->data()),
                    req.pubkey_ed25519->size()};

        return d;
    }

}  // namespace

// Aliases used in `load_fields<...>` to make formatting less obtuse
using Str = std::string;
using SV = std::string_view;
using TP = system_clock::time_point;
template <typename T>
using Vec = std::vector<T>;

template <typename Dict>
static void load(store& s, Dict& d) {
    auto [data, expiry, msg_ns, pubkey_alt, pubkey, pk_ed25519, sig_ts, sig, subacc, subacc_sig] =
            load_fields<SV, TP, namespace_id, Str, Str, SV, TP, SV, SV, SV>(
                    d,
                    "data",
                    "expiry",
                    "namespace",
                    "pubKey",
                    "pubkey",
                    "pubkey_ed25519",
                    "sig_timestamp",
                    "signature",
                    "subaccount",
                    "subaccount_sig");

    // timestamp and ttl are special snowflakes: for backwards compat reasons, they can
    // be passed as strings when loading from json.
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

    require("timestamp", timestamp);
    require_exactly_one_of("expiry", expiry, "ttl", ttl);
    s.timestamp = *timestamp;
    s.expiry = expiry ? *expiry : s.timestamp + std::chrono::milliseconds{*ttl};

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubkey_alt, true);
    auto& pk = pubkey ? pubkey : pubkey_alt;

    if (msg_ns)
        s.msg_namespace = *msg_ns;

    if (sig) {
        load_pk_signature(s, d, pk, pk_ed25519, sig);
        load_subaccount(s, d, subacc, subacc_sig);
        s.sig_ts = sig_ts.value_or(s.timestamp);
    } else
        load_pk(s, pk);

    require("data", data);
    if constexpr (std::is_same_v<Dict, json>) {
        // For json we require data be base64 encoded
        if (!oxenc::is_base64(*data))
            throw parse_error{"Invalid 'data' value: not base64 encoded"};
        static_assert(
                store::MAX_MESSAGE_BODY % 3 == 0,
                "MAX_MESSAGE_BODY should be divisible by 3 so that max base64 encoded size "
                "avoids padding");
        if (data->size() > store::MAX_MESSAGE_BODY / 3 * 4)
            throw parse_error{fmt::format(
                    "Message body exceeds maximum allowed length of {} bytes",
                    store::MAX_MESSAGE_BODY)};
        s.data = oxenc::from_base64(*data);
    } else {
        // Otherwise (i.e. bencoded) then we take data as bytes
        if (data->size() > store::MAX_MESSAGE_BODY)
            throw parse_error{fmt::format(
                    "Message body exceeds maximum allowed length of {} bytes",
                    store::MAX_MESSAGE_BODY)};
        s.data = *data;
    }
}
void store::load_from(json params) {
    load(*this, params);
}
void store::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value store::to_bt() const {
    bt_dict d = to_bt_common(*this);
    d["timestamp"] = to_epoch_ms(timestamp);
    d["expiry"] = to_epoch_ms(expiry);
    d["data"] = std::string_view{data};
    if (sig_ts)
        d["sig_timestamp"] = to_epoch_ms(*sig_ts);
    if (msg_namespace != namespace_id::Default)
        d["namespace"] = static_cast<std::underlying_type_t<namespace_id>>(msg_namespace);
    return d;
}

template <typename Dict>
static void load(retrieve& r, Dict& d) {
    auto [lastHash,
          last_hash,
          max_count,
          max_size,
          msg_ns,
          pubKey,
          pubkey,
          pk_ed25519,
          sig,
          subacc,
          subacc_sig,
          ts] =
            load_fields<Str, Str, int, int, namespace_id, Str, Str, SV, SV, SV, SV, TP>(
                    d,
                    "lastHash",
                    "last_hash",
                    "max_count",
                    "max_size",
                    "namespace",
                    "pubKey",
                    "pubkey",
                    "pubkey_ed25519",
                    "signature",
                    "subaccount",
                    "subaccount_sig",
                    "timestamp");

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubKey, true);
    auto& pk = pubkey ? pubkey : pubKey;

    if (pk_ed25519 || sig || ts || (msg_ns && *msg_ns != namespace_id::LegacyClosed)) {
        load_pk_signature(r, d, pk, pk_ed25519, sig);
        load_subaccount(r, d, subacc, subacc_sig);
        r.timestamp = std::move(*ts);
        r.check_signature = true;
    } else {
        load_pk(r, pk);
    }

    if (msg_ns)
        r.msg_namespace = *msg_ns;

    require_at_most_one_of("last_hash", last_hash, "lastHash", lastHash);
    if (lastHash)
        last_hash = std::move(lastHash);
    if (last_hash) {
        if (last_hash->empty())  // Treat empty string as not provided
            last_hash.reset();
        else if (last_hash->size() == 43) {
            if (!oxenc::is_base64(*last_hash))
                throw parse_error{"Invalid last_hash: not base64"};
        } else
            throw parse_error{"Invalid last_hash: expected base64 (43 chars)"};
    }
    r.last_hash = std::move(last_hash);

    r.max_count = max_count;
    r.max_size = max_size;
}
void retrieve::load_from(json params) {
    load(*this, params);
}
void retrieve::load_from(bt_dict_consumer params) {
    load(*this, params);
}

static bool is_valid_message_hash(std::string_view hash) {
    return (hash.size() == 43 && oxenc::is_base64(hash));
}

template <typename Dict>
static void load(delete_msgs& dm, Dict& d) {
    auto [messages, pubkey, pubkey_ed25519, required, signature, subacc, subacc_sig] =
            load_fields<Vec<Str>, Str, SV, bool, SV, SV, SV>(
                    d,
                    "messages",
                    "pubkey",
                    "pubkey_ed25519",
                    "required",
                    "signature",
                    "subaccount",
                    "subaccount_sig");

    load_pk_signature(dm, d, pubkey, pubkey_ed25519, signature);
    load_subaccount(dm, d, subacc, subacc_sig);
    require("messages", messages);
    dm.messages = std::move(*messages);
    if (dm.messages.empty())
        throw parse_error{"messages does not contain any message hashes"};
    dm.required = required.value_or(false);
    for (const auto& m : dm.messages)
        if (!is_valid_message_hash(m))
            throw parse_error{"invalid message hash: " + m};
}
void delete_msgs::load_from(json params) {
    load(*this, params);
}
void delete_msgs::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value delete_msgs::to_bt() const {
    bt_dict ret = to_bt_common(*this);
    bt_list msgs;
    for (auto& m : messages)
        msgs.emplace_back(std::string_view{m});
    ret["messages"] = std::move(msgs);
    return ret;
}

template <typename Dict>
static void load(revoke_subaccount& rs, Dict& d) {
    auto [pubkey, pubkey_ed25519, revoke, signature, timestamp] = load_fields<Str, SV, SV, SV, TP>(
            d, "pubkey", "pubkey_ed25519", "revoke", "signature", "timestamp");
    load_pk_signature(rs, d, pubkey, pubkey_ed25519, signature);
    require("revoke", revoke);
    const auto& sa = *revoke;
    if constexpr (std::is_same_v<json, Dict>) {
        if (oxenc::is_base64(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 4 / 3)
            oxenc::from_base64(sa.begin(), sa.end(), rs.revoke.token.begin());
        else if (oxenc::is_hex(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 2)
            oxenc::from_hex(sa.begin(), sa.end(), rs.revoke.token.begin());
        else
            throw parse_error{"invalid revoke: expected base64 or hex-encoded subaccount tag"};
    } else {
        if (sa.size() != SUBACCOUNT_TOKEN_LENGTH)
            throw parse_error{"invalid revoke subaccount: invalid subaccount tag length"};
        std::memcpy(rs.revoke.token.data(), sa.data(), SUBACCOUNT_TOKEN_LENGTH);
    }
    require("timestamp", timestamp);
    rs.timestamp = *timestamp;
}
void revoke_subaccount::load_from(json params) {
    load(*this, params);
}
void revoke_subaccount::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value revoke_subaccount::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["revoke"] = revoke.sview();
    ret["timestamp"] = to_epoch_ms(timestamp);
    return ret;
}

template <typename Dict>
static void load(unrevoke_subaccount& us, Dict& d) {
    auto [pubkey, pubkey_ed25519, signature, timestamp, unrevoke] =
            load_fields<Str, SV, SV, TP, SV>(
                    d, "pubkey", "pubkey_ed25519", "signature", "timestamp", "unrevoke");
    load_pk_signature(us, d, pubkey, pubkey_ed25519, signature);
    require("timestamp", timestamp);
    us.timestamp = *timestamp;
    require("unrevoke", unrevoke);
    const auto& sa = *unrevoke;
    if constexpr (std::is_same_v<json, Dict>) {
        if (oxenc::is_base64(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 4 / 3)
            oxenc::from_base64(sa.begin(), sa.end(), us.unrevoke.token.begin());
        else if (oxenc::is_hex(sa) && sa.size() == SUBACCOUNT_TOKEN_LENGTH * 2)
            oxenc::from_hex(sa.begin(), sa.end(), us.unrevoke.token.begin());
        else
            throw parse_error{"invalid unrevoke: expected base64 or hex-encoded subaccount tag"};
    } else {
        if (sa.size() != SUBACCOUNT_TOKEN_LENGTH)
            throw parse_error{"invalid unrevoke subaccount: invalid subaccount tag length"};
        std::memcpy(us.unrevoke.token.data(), sa.data(), SUBACCOUNT_TOKEN_LENGTH);
    }
}
void unrevoke_subaccount::load_from(json params) {
    load(*this, params);
}
void unrevoke_subaccount::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value unrevoke_subaccount::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["timestamp"] = to_epoch_ms(timestamp);
    ret["unrevoke"] = unrevoke.sview();
    return ret;
}

template <typename Dict>
static void load(delete_all& da, Dict& d) {
    auto [msgs_ns, pubkey, pubkey_ed25519, signature, subacc, subacc_sig, timestamp] =
            load_fields<namespace_var, Str, SV, SV, SV, SV, TP>(
                    d,
                    "namespace",
                    "pubkey",
                    "pubkey_ed25519",
                    "signature",
                    "subaccount",
                    "subaccount_sig",
                    "timestamp");

    load_pk_signature(da, d, pubkey, pubkey_ed25519, signature);
    load_subaccount(da, d, subacc, subacc_sig);
    require("timestamp", timestamp);
    da.msg_namespace = msgs_ns.value_or(namespace_id::Default);
    da.timestamp = std::move(*timestamp);
}
void delete_all::load_from(json params) {
    load(*this, params);
}
void delete_all::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value delete_all::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["timestamp"] = to_epoch_ms(timestamp);
    set_variant(ret, "namespace", msg_namespace);
    return ret;
}

template <typename Dict>
static void load(delete_before& db, Dict& d) {
    auto [before, msgs_ns, pubkey, pubkey_ed25519, signature, subacc, subacc_sig] =
            load_fields<TP, namespace_var, Str, SV, SV, SV, SV>(
                    d,
                    "before",
                    "namespace",
                    "pubkey",
                    "pubkey_ed25519",
                    "signature",
                    "subaccount",
                    "subaccount_sig");

    load_pk_signature(db, d, pubkey, pubkey_ed25519, signature);
    load_subaccount(db, d, subacc, subacc_sig);
    require("before", before);
    db.before = std::move(*before);
    db.msg_namespace = msgs_ns.value_or(namespace_id::Default);
}
void delete_before::load_from(json params) {
    load(*this, params);
}
void delete_before::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value delete_before::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["before"] = to_epoch_ms(before);
    set_variant(ret, "namespace", msg_namespace);
    return ret;
}

template <typename Dict>
static void load(expire_all& e, Dict& d) {
    auto [expiry, msgs_ns, pubkey, pubkey_ed25519, signature, subacc, subacc_sig] =
            load_fields<TP, namespace_var, Str, SV, SV, SV, SV>(
                    d,
                    "expiry",
                    "namespace",
                    "pubkey",
                    "pubkey_ed25519",
                    "signature",
                    "subaccount",
                    "subaccount_sig");

    load_pk_signature(e, d, pubkey, pubkey_ed25519, signature);
    load_subaccount(e, d, subacc, subacc_sig);
    require("expiry", expiry);
    e.expiry = std::move(*expiry);
    e.msg_namespace = msgs_ns.value_or(namespace_id::Default);
}
void expire_all::load_from(json params) {
    load(*this, params);
}
void expire_all::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value expire_all::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["expiry"] = to_epoch_ms(expiry);
    set_variant(ret, "namespace", msg_namespace);
    return ret;
}

template <typename Dict>
static void load(expire_msgs& e, Dict& d) {
    auto [expiry,
          extend,
          messages,
          pubkey,
          pubkey_ed25519,
          shorten,
          signature,
          subacc,
          subacc_sig] =
            load_fields<TP, bool, Vec<Str>, Str, SV, bool, SV, SV, SV>(
                    d,
                    "expiry",
                    "extend",
                    "messages",
                    "pubkey",
                    "pubkey_ed25519",
                    "shorten",
                    "signature",
                    "subaccount",
                    "subaccount_sig");

    load_pk_signature(e, d, pubkey, pubkey_ed25519, signature);
    load_subaccount(e, d, subacc, subacc_sig);
    require("expiry", expiry);
    e.expiry = std::move(*expiry);
    e.shorten = shorten.value_or(false);
    e.extend = extend.value_or(false);
    if (e.shorten && e.extend)
        throw parse_error{"cannot specify both 'shorten' and 'extend'"};
    require("messages", messages);
    e.messages = std::move(*messages);
    if (e.messages.empty())
        throw parse_error{"messages does not contain any message hashes"};
    for (const auto& m : e.messages)
        if (!is_valid_message_hash(m))
            throw parse_error{"invalid message hash: " + m};
}
void expire_msgs::load_from(json params) {
    load(*this, params);
}
void expire_msgs::load_from(bt_dict_consumer params) {
    load(*this, params);
}
bt_value expire_msgs::to_bt() const {
    auto ret = to_bt_common(*this);
    ret["expiry"] = to_epoch_ms(expiry);
    if (shorten)
        ret["shorten"] = 1;
    if (extend)
        ret["extend"] = 1;
    bt_list msgs;
    for (const auto& m : messages)
        msgs.emplace_back(std::string_view{m});
    ret["messages"] = std::move(msgs);
    return ret;
}

template <typename Dict>
static void load(get_expiries& ge, Dict& d) {
    auto [messages, pubkey, pk_ed25519, sig, subacc, subacc_sig, timestamp] =
            load_fields<Vec<Str>, Str, SV, SV, SV, SV, TP>(
                    d,
                    "messages",
                    "pubkey",
                    "pubkey_ed25519",
                    "signature",
                    "subaccount",
                    "subaccount_sig",
                    "timestamp");

    load_pk_signature(ge, d, pubkey, pk_ed25519, sig);
    load_subaccount(ge, d, subacc, subacc_sig);
    require("timestamp", timestamp);
    ge.sig_ts = *timestamp;
    require("messages", messages);
    ge.messages = std::move(*messages);
    if (ge.messages.empty())
        throw parse_error{"messages does not contain any message hashes"};
}
void get_expiries::load_from(json params) {
    load(*this, params);
}
void get_expiries::load_from(bt_dict_consumer params) {
    load(*this, params);
}

template <typename Dict>
static void load(get_swarm& g, Dict& d) {
    auto [pubKey, pubkey] = load_fields<Str, Str>(d, "pubKey", "pubkey");

    require_exactly_one_of("pubkey", pubkey, "pubKey", pubKey, true);
    if (!g.pubkey.load(std::move(pubkey ? *pubkey : *pubKey)))
        throw parse_error{fmt::format(
                "Pubkey must be {} hex digits/{} bytes long",
                USER_PUBKEY_SIZE_HEX,
                USER_PUBKEY_SIZE_BYTES)};
}
void get_swarm::load_from(json params) {
    load(*this, params);
}
void get_swarm::load_from(bt_dict_consumer params) {
    load(*this, params);
}

inline const static std::unordered_set<std::string_view> allowed_oxend_endpoints{
        {"get_service_nodes"sv, "ons_resolve"sv}};

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
void oxend_request::load_from(json params) {
    load(*this, params);
}
void oxend_request::load_from(bt_dict_consumer params) {
    load(*this, params);
}

static client_subrequest as_subrequest(client_request&& req) {
    return var::visit(
            [](auto&& r) -> client_subrequest {
                using T = std::decay_t<decltype(r)>;
                if constexpr (type_list_contains<T, client_rpc_subrequests>)
                    return std::move(r);
                else
                    throw parse_error{
                            "Invalid batch subrequest: subrequests may not contain meta-requests"};
            },
            std::move(req));
}

void batch::load_from(json params) {
    auto reqs_it = params.find("requests");
    if (reqs_it == params.end() || !reqs_it->is_array() || reqs_it->empty())
        throw parse_error{"Invalid batch request: no valid \"requests\" field"};
    if (reqs_it->size() > BATCH_REQUEST_MAX)
        throw parse_error{"Invalid batch request: subrequest limit exceeded"};

    for (auto& j : *reqs_it) {
        if (!j.is_object())
            throw parse_error{"Invalid batch request: requests must be objects"};
        auto meth_it = j.find("method");
        auto params_it = j.find("params");
        if (meth_it == j.end() || params_it == j.end() || !meth_it->is_string() ||
            !params_it->is_object())
            throw parse_error{"Invalid batch request: subrequests must have method/params keys"};
        auto method = meth_it->get<std::string_view>();
        auto rpc_it = RequestHandler::client_rpc_endpoints.find(method);
        if (rpc_it == RequestHandler::client_rpc_endpoints.end())
            throw parse_error{
                    "Invalid batch subrequest: invalid method \"" + std::string{method} + "\""};
        subreqs.push_back(as_subrequest(rpc_it->second.load_req(std::move(*params_it))));
    }
}
void batch::load_from(bt_dict_consumer params) {
    if (!params.skip_until("requests") || !params.is_list())
        throw parse_error{"Invalid batch request: no valid \"requests\" field"};

    auto requests = params.consume_list_consumer();
    while (!requests.is_finished()) {
        if (!requests.is_dict())
            throw parse_error{"Invalid batch request: requests must be dicts"};
        if (subreqs.size() >= BATCH_REQUEST_MAX)
            throw parse_error{"Invalid batch request: subrequest limit exceeded"};
        auto sr = requests.consume_dict_consumer();
        if (!sr.skip_until("method") || !sr.is_string())
            throw parse_error{"Invalid batch request: subrequests must have a method"};
        auto method = sr.consume_string_view();
        auto rpc_it = RequestHandler::client_rpc_endpoints.find(method);
        if (rpc_it == RequestHandler::client_rpc_endpoints.end())
            throw parse_error{
                    "Invalid batch subrequest: invalid method \"" + std::string{method} + "\""};
        if (!sr.skip_until("params") || !sr.is_dict())
            throw parse_error{"Invalid batch request: subrequests must have a params dict"};
        subreqs.push_back(as_subrequest(rpc_it->second.load_req(sr.consume_dict_consumer())));
    }
    if (subreqs.empty())
        throw parse_error{"Invalid batch request: empty \"requests\" list"};
}

// Copies an optional vector into a fixed-size array, substituting 0's for omitted vector elements,
// and ignoring anything in the vector longer than the given size.  Gives nullopt if the input
// vector is itself nullopt or empty.
template <size_t N, typename T>
static std::optional<std::array<T, N>> to_fixed_array(const std::optional<std::vector<T>>& in) {
    if (!in || in->empty())
        return std::nullopt;
    std::array<T, N> out;
    for (size_t i = 0; i < N; i++)
        out[i] = i < in->size() ? (*in)[i] : T{0};
    return out;
}

template <typename Dict>
static void load_condition(ifelse& i, Dict if_) {
    auto [height_ge_, height_lt_, hf_ge_, hf_lt_, v_ge_, v_lt_] =
            load_fields<int, int, Vec<int>, Vec<int>, Vec<int>, Vec<int>>(
                    if_,
                    "height_at_least",
                    "height_before",
                    "hf_at_least",
                    "hf_before",
                    "v_at_least",
                    "v_before");

    auto hf_ge = to_fixed_array<2>(hf_ge_);
    auto hf_lt = to_fixed_array<2>(hf_lt_);
    auto v_ge = to_fixed_array<3>(v_ge_);
    auto v_lt = to_fixed_array<3>(v_lt_);
    auto height_ge = height_ge_;
    auto height_lt = height_lt_;

    if (!(height_ge_ || height_lt_ || hf_ge || hf_lt || v_ge || v_lt))
        throw parse_error{"Invalid ifelse request: must specify at least one \"if\" condition"};

    i.condition = [=](const snode::ServiceNode& snode) {
        bool result = true;
        if (hf_ge || hf_lt) {
            std::array<int, 2> hf = {snode.hf().first, snode.hf().second};
            if (hf_ge)
                result &= hf >= *hf_ge;
            if (hf_lt)
                result &= hf < *hf_lt;
        }
        if (v_ge || v_lt) {
            std::array<int, 3> v = {
                    STORAGE_SERVER_VERSION[0],
                    STORAGE_SERVER_VERSION[1],
                    STORAGE_SERVER_VERSION[2]};
            if (v_ge)
                result &= v >= *v_ge;
            if (v_lt)
                result &= v < *v_lt;
        }
        if (height_ge || height_lt) {
            auto height = static_cast<int>(snode.blockheight());
            if (height_ge)
                result &= height >= *height_ge;
            if (height_lt)
                result &= height < *height_lt;
        }
        return result;
    };
}

static std::unique_ptr<client_request> load_ifelse_request(json& params, const std::string& key) {
    auto it = params.find(key);
    if (it == params.end())
        return nullptr;
    if (!it->is_object())
        throw parse_error{"Invalid ifelse request: " + key + " must be an object"};
    auto mit = it->find("method");
    auto pit = it->find("params");
    if (mit == it->end() || !mit->is_string() || pit == it->end())
        throw parse_error{"Invalid ifelse request: " + key + " must have method/params keys"};
    auto method = mit->get<std::string_view>();
    auto rpc_it = RequestHandler::client_rpc_endpoints.find(method);
    if (rpc_it == RequestHandler::client_rpc_endpoints.end())
        throw parse_error{"Invalid ifelse request method \"" + key + "\""};

    return var::visit(
            [](auto&& r) { return std::make_unique<client_request>(std::move(r)); },
            rpc_it->second.load_req(std::move(*pit)));
}

static std::unique_ptr<client_request> load_ifelse_request(
        bt_dict_consumer& params, const std::string& key) {
    if (!params.skip_until(key))
        return nullptr;
    if (!params.is_dict())
        throw parse_error{"Invalid ifelse request: " + key + " must be a dict"};
    auto req = params.consume_dict_consumer();
    if (!req.skip_until("method") || !req.is_string())
        throw parse_error{"Invalid ifelse request: " + key + " missing method"};
    auto method = req.consume_string_view();
    auto rpc_it = RequestHandler::client_rpc_endpoints.find(method);
    if (rpc_it == RequestHandler::client_rpc_endpoints.end())
        throw parse_error{"Invalid ifelse request method \"" + key + "\""};

    if (!req.skip_until("params") || !req.is_dict())
        throw parse_error{"Invalid ifelse request: " + key + " missing params"};
    return var::visit(
            [](auto&& r) { return std::make_unique<client_request>(std::move(r)); },
            rpc_it->second.load_req(req.consume_dict_consumer()));
}

void ifelse::load_from(json params) {
    auto cond_it = params.find("if");
    if (cond_it == params.end() || !cond_it->is_object())
        throw parse_error{"Invalid ifelse request: no valid \"if\" field"};
    load_condition(*this, std::move(*cond_it));

    action_true = load_ifelse_request(params, "then");
    action_false = load_ifelse_request(params, "else");
    if (!action_true && !action_false)
        throw parse_error{"Invalid ifelse request: at least one of \"then\"/\"else\" required"};
}
void ifelse::load_from(bt_dict_consumer params) {
    action_false = load_ifelse_request(params, "else");
    if (!params.skip_until("if") || !params.is_dict())
        throw parse_error{"Invalid ifelse request: no valid \"if\" field"};
    load_condition(*this, params.consume_dict_consumer());
    action_true = load_ifelse_request(params, "then");
    if (!action_true && !action_false)
        throw parse_error{"Invalid ifelse request: at least one of \"then\"/\"else\" required"};
}

}  // namespace oxenss::rpc
