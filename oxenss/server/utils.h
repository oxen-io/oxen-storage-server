#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <oxenss/common/format.h>
#include <oxenss/common/namespace.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>

#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <oxenc/bt.h>

namespace oxenss {

namespace rpc {
    struct OnionRequestMetadata;
}  // namespace rpc

// place this here so we can use it in oxenss::*
using namespace std::literals;

// {pubkey (bytes), pubkey (hex), namespaces, want_data}
using sub_info = std::tuple<std::string, std::string, std::vector<namespace_id>, bool>;

oxenc::bt_value json_to_bt(nlohmann::json j);

nlohmann::json bt_to_json(oxenc::bt_dict_consumer d);

nlohmann::json bt_to_json(oxenc::bt_list_consumer l);

void handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<sub_info>& subs);

void handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<sub_info>& subs);

std::string encode_onion_data(std::string_view payload, const rpc::OnionRequestMetadata& data);

std::pair<std::string_view, rpc::OnionRequestMetadata> decode_onion_data(std::string_view data);

inline std::string serialize_response(oxenc::bt_dict supplement = {}) {
    return oxenc::bt_serialize(supplement);
}

inline std::string serialize_error(int ec, std::string msg, bool bt_encoded) {
    auto resp = nlohmann::json::array({ec, std::move(msg)});
    return bt_encoded ? oxenc::bt_serialize(json_to_bt(std::move(resp))) : resp.dump();
}

enum class MonitorResponse {
    BAD_ARGS = 1,
    BAD_PUBKEY = 2,
    BAD_NS = 3,
    BAD_TS = 4,
    BAD_SIG = 5,
    WRONG_SWARM = 6,
};

inline void monitor_error(oxenc::bt_dict_producer& out, MonitorResponse r, std::string message) {
    out.append("errcode", static_cast<std::underlying_type_t<MonitorResponse>>(r));
    out.append("error", std::move(message));
}

// Quic request errors and codes
namespace quic {
    inline constexpr auto BAD_REQUEST{400};
    inline constexpr auto INTERNAL_SERVER_ERROR{500};
}  // namespace quic

}  // namespace oxenss

/// Namespace for http constants/types
namespace oxenss::http {

// HTTP response status code
using response_code = std::pair<int, std::string_view>;
inline constexpr response_code OK{200, "OK"sv}, BAD_REQUEST{400, "Bad Request"sv},
        UNAUTHORIZED{401, "Unauthorized"sv}, FORBIDDEN{403, "Forbidden"sv},
        NOT_FOUND{404, "Not Found"sv}, NOT_ACCEPTABLE{406, "Not Acceptable"sv}, GONE{410, "Gone"sv},
        PAYLOAD_TOO_LARGE{413, "Payload Too Large"sv},
        MISDIRECTED_REQUEST{421, "Misdirected Request"sv},
        TOO_MANY_REQUESTS{429, "Too Many Requests"sv},
        INTERNAL_SERVER_ERROR{500, "Internal Server Error"sv}, BAD_GATEWAY{502, "Bad Gateway"sv},
        SERVICE_UNAVAILABLE{503, "Service Unavailable"sv},
        GATEWAY_TIMEOUT{504, "Gateway Timeout"sv};

inline constexpr response_code from_code(int status) {
    switch (status) {
        case 200: return OK;
        case 400: return BAD_REQUEST;
        case 401: return UNAUTHORIZED;
        case 403: return FORBIDDEN;
        case 404: return NOT_FOUND;
        case 406: return NOT_ACCEPTABLE;
        case 410: return GONE;
        case 413: return PAYLOAD_TOO_LARGE;
        case 421: return MISDIRECTED_REQUEST;
        case 429: return TOO_MANY_REQUESTS;
        case 502: return BAD_GATEWAY;
        case 503: return SERVICE_UNAVAILABLE;
        case 504: return GATEWAY_TIMEOUT;
        default: [[fallthrough]];
        case 500: return INTERNAL_SERVER_ERROR;
    }
}

namespace detail {
    struct ascii_lc_hash {
        std::size_t operator()(const std::string& val) const {
            return std::hash<std::string>{}(util::lowercase_ascii_string(val));
        }
    };
    struct ascii_lc_equal {
        bool operator()(const std::string& lhs, const std::string& rhs) const {
            return util::lowercase_ascii_string(lhs) == util::lowercase_ascii_string(rhs);
        }
    };
}  // namespace detail

// A case-insensitive (but case-preserving) unordered_map for holding header fields
using headers =
        std::unordered_map<std::string, std::string, detail::ascii_lc_hash, detail::ascii_lc_equal>;

// Returned in a HF19+ ping_test to include the remote's pubkey in the response
inline constexpr auto SNODE_PUBKEY_HEADER = "X-Oxen-Snode-Pubkey";

}  // namespace oxenss::http
