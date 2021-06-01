#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "string_utils.hpp"

/// Namespace for http constants/types
namespace oxen::http {

    using namespace std::literals;

    // HTTP response status code
    using response_code = std::pair<int, std::string_view>;
    inline constexpr response_code
          OK{200, "OK"sv},
          BAD_REQUEST{400, "Bad Request"sv},
          UNAUTHORIZED{401, "Unauthorized"sv},
          FORBIDDEN{403, "Forbidden"sv},
          NOT_FOUND{404, "Not Found"sv},
          NOT_ACCEPTABLE{406, "Not Acceptable"sv},
          GONE{410, "Gone"sv},
          PAYLOAD_TOO_LARGE{413, "Payload Too Large"sv},
          MISDIRECTED_REQUEST{421, "Misdirected Request"sv},
          TOO_MANY_REQUESTS{429, "Too Many Requests"sv},
          INTERNAL_SERVER_ERROR{500, "Internal Server Error"sv},
          BAD_GATEWAY{502, "Bad Gateway"sv},
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

    // Common mime types
    inline constexpr std::string_view plaintext = "text/plain"sv;
    inline constexpr std::string_view json = "application/json"sv;

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
    }

    // A case-insensitive (but case-preserving) unordered_map for holding header fields
    using headers = std::unordered_map<std::string, std::string, detail::ascii_lc_hash, detail::ascii_lc_equal>;

    // Deprecated headers; these can be removed after HF19
    constexpr auto SNODE_SENDER_HEADER = "X-Loki-Snode-PubKey";
    constexpr auto SNODE_TARGET_HEADER = "X-Target-Snode-Key";
    constexpr auto SNODE_SIGNATURE_HEADER = "X-Loki-Snode-Signature";
    constexpr auto SENDER_KEY_HEADER = "X-Sender-Public-Key";

    // Returned in a HF19+ ping_test to include the remote's pubkey in the response
    constexpr auto SNODE_PUBKEY_HEADER = "X-Oxen-Snode-Pubkey";
}


