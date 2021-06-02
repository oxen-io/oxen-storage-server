#include "client_rpc_endpoints.h"
#include "oxen_logger.h"
#include "string_utils.hpp"

#include <chrono>
#include <type_traits>
#include <unordered_set>
#include <variant>

#include <oxenmq/base64.h>
#include <oxenmq/hex.h>

namespace oxen::rpc {

using nlohmann::json;

namespace {

// Extracts a field suitable for a `T` value from the given json with name `name`.  Takes the json
// params and any number of aliases for `name`.  Throws if it encounters an invalid value or
// encounters more than one value (via aliases) for the same option.  Returns nullopt if the field
// isn't present or is present and set to null.
template <typename T, typename... Alias, typename = std::enable_if_t<(... && std::is_same_v<Alias, const char*>)>>
std::optional<T> parse_field(const json& params, const char* name, Alias... aliases) {
    static_assert(std::is_unsigned_v<T> || std::is_integral_v<T> ||
            std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>);
    std::optional<T> res;
    const char* found = nullptr;
    for (const auto& name : {name, aliases...}) {
        if (auto it = params.find(name); it != params.end()) {
            if (found)
                throw parse_error{"Cannot specify both '"s + name + "' and '"s + found + "'"s};
            found = name;

            // Accept null as a non-value (i.e. we'll return std::nullopt)
            if (it->is_null())
                continue;

            bool right_type =
                std::is_same_v<T, bool> ? it->is_boolean() :
                std::is_unsigned_v<T> ? it->is_number_unsigned() :
                std::is_integral_v<T> ? it->is_number_integer() :
                it->is_string();
            if (!right_type)
                throw parse_error{fmt::format("Invalid value type given for '{}': {}", name, it->dump())};
            if constexpr (std::is_same_v<T, std::string_view>)
                res = it->template get_ref<const std::string&>();
            else
                res = it->template get<T>();
        }
    }
    return res;
}

// Same as above, but throws if no value (or `null`) is present
template <typename T, typename... Args>
T parse_required_field(const json& params, const char* name, Args&&... args) {
    if (auto maybe = parse_field<T>(params, name, std::forward<Args>(args)...))
        return *maybe;
    throw parse_error{fmt::format("Required field '{}' missing", name)};
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
    return parse_field<T>(params, {name});
}
template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
T parse_required_stringified(const json& params, const char* name) {
    if (auto maybe = parse_stringified<T>(params, name))
        return *maybe;
    throw parse_error{fmt::format("Required field '{}' missing", name)};
}

template <typename T1, typename T2>
void require_exactly_one_of(const char* first, const std::optional<T1>& a, const char* second, const std::optional<T2>& b) {
    if (a && b)
        throw parse_error{fmt::format("Cannot specify both '{}' and '{}'", first, second)};
    if (!(a || b))
        throw parse_error{fmt::format("Required field '{}' or '{}' missing", first, second)};
}

} // anon. namespace

void store::load_from(json params) {
    if (!pubkey.load(parse_required_field<std::string>(params, "pubkey", "pubKey")))
        throw parse_error{fmt::format("Pubkey must be {} hex digits long", get_user_pubkey_size())};

    timestamp = std::chrono::system_clock::time_point{std::chrono::milliseconds{
        parse_required_stringified<uint64_t>(params, "timestamp")}};
    auto ttl_in = parse_stringified<uint64_t>(params, "ttl");
    auto expiry_in = parse_field<uint64_t>(params, "expiry");
    require_exactly_one_of("ttl", ttl_in, "expiry", expiry_in);
    expiry = ttl_in
        ? timestamp + std::chrono::milliseconds{*ttl_in}
        : std::chrono::system_clock::time_point{std::chrono::milliseconds{*expiry_in}};

    auto b64_in = parse_required_field<std::string_view>(params, "data");
    if (!oxenmq::is_base64(b64_in))
        throw parse_error{"Invalid 'data' value: not base64 encoded"};

    static_assert(MAX_MESSAGE_BODY % 3 == 0,
            "MAX_MESSAGE_BODY should be divisible by 3 so that max base64 encoded size is exact (no padding)");
    if (b64_in.size() > MAX_MESSAGE_BODY / 3 * 4)
        throw parse_error{fmt::format("Message body exceeds maximum allowed length of {} bytes",
                MAX_MESSAGE_BODY)};
}

void retrieve::load_from(json params) {
    if (!pubkey.load(parse_required_field<std::string>(params, "pubkey", "pubKey")))
        throw parse_error{fmt::format("Pubkey must be {} hex digits long", get_user_pubkey_size())};

    last_hash = parse_field<std::string>(params, "last_hash", "lastHash");
    if (last_hash) {
        if (last_hash->empty()) // Treat empty string as not provided
            last_hash.reset();
        else if (last_hash->size() != 128 || !oxenmq::is_hex(*last_hash))
            throw parse_error{"last_hash must be 128 hex digits long"};
    }
}

void get_swarm::load_from(json params) {
    if (!pubkey.load(parse_required_field<std::string>(params, "pubkey", "pubKey")))
        throw parse_error{fmt::format("Pubkey must be {} hex digits long", get_user_pubkey_size())};
}

inline const static std::unordered_set<std::string_view> allowed_oxend_endpoints{{
    "get_service_nodes"sv, "ons_resolve"sv}};

void oxend_request::load_from(json params) {
    auto endpoint = parse_required_field<std::string_view>(params, "endpoint");
    if (!allowed_oxend_endpoints.count(endpoint))
        throw parse_error{fmt::format("Invalid oxend endpoint '{}'", endpoint)};
    if (auto it = params.find("params"); it != params.end() && !it->is_null()) {
        if (!it->is_object())
            throw parse_error{"Invalid oxend 'params': not a dict"};
        this->params = std::move(*it);
    }
}

} // namespace oxen::rpc
