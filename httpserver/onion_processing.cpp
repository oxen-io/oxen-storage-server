#include "channel_encryption.hpp"
#include "loki_logger.h"
#include "request_handler.h"
#include "service_node.h"
#include "utils.hpp"

/// This is only included because of `parse_combined_payload`,
/// in the future it will be moved
#include "http_connection.h"

#include <charconv>
#include <variant>

using nlohmann::json;

namespace loki {

/// The request is to be forwarded to another SS node
struct RelayToNodeInfo {
    /// Inner ciphertext for next node
    std::string ciphertext;
    // Key to be forwarded to next node for decryption
    std::string ephemeral_key;
    // Next node's ed25519 key
    std::string next_node;
};

/// The request is to be forwarded to some non-SS server
/// that supports our protocol (e.g. Session File Server)
struct RelayToServerInfo {
    // Result of decryption (intact)
    std::string payload;
    // Server's address
    std::string host;
    // Request's target
    std::string target;
};

/// We are the final destination for this request
struct FinalDesitnationInfo {
    std::string body;
};

enum class ProcessCiphertextError {
    INVALID_CIPHERTEXT,
    INVALID_JSON,
};

using ParsedInfo = std::variant<RelayToNodeInfo, RelayToServerInfo,
                                FinalDesitnationInfo, ProcessCiphertextError>;

static auto
process_ciphertext_v1(const ChannelEncryption<std::string>& decryptor,
                      const std::string& ciphertext,
                      const std::string& ephem_key) -> ParsedInfo {

    std::string plaintext;

    try {
        const std::string ciphertext_bin = util::base64_decode(ciphertext);

        plaintext = decryptor.decrypt_gcm(ciphertext_bin, ephem_key);
    } catch (const std::exception& e) {
        LOKI_LOG(debug, "Error decrypting an onion request: {}", e.what());
        return ProcessCiphertextError::INVALID_CIPHERTEXT;
    }

    LOKI_LOG(debug, "onion request decrypted: (len: {})", plaintext.size());

    try {

        const json inner_json = json::parse(plaintext, nullptr, true);

        if (inner_json.find("body") != inner_json.end()) {

            auto body = inner_json.at("body").get_ref<const std::string&>();

            LOKI_LOG(debug, "Found body: <{}>", body);
            return FinalDesitnationInfo{body};
        } else if (inner_json.find("host") != inner_json.end()) {

            const auto& host =
                inner_json.at("host").get_ref<const std::string&>();
            const auto& target =
                inner_json.at("target").get_ref<const std::string&>();
            return RelayToServerInfo{plaintext, host, target};

        } else {
            // We fall back to forwarding a request to the next node
            const auto& ciphertext =
                inner_json.at("ciphertext").get_ref<const std::string&>();
            const auto& dest =
                inner_json.at("destination").get_ref<const std::string&>();
            const auto& ekey =
                inner_json.at("ephemeral_key").get_ref<const std::string&>();

            return RelayToNodeInfo{ciphertext, ekey, dest};
        }

    } catch (std::exception& e) {
        LOKI_LOG(debug, "Error parsing inner JSON in onion request: {}",
                 e.what());
        return ProcessCiphertextError::INVALID_JSON;
    }
}

static auto
process_ciphertext_v2(const ChannelEncryption<std::string>& decryptor,
                      const std::string& ciphertext,
                      const std::string& ephem_key) -> ParsedInfo {
    std::string plaintext;

    try {
        plaintext = decryptor.decrypt_gcm(ciphertext, ephem_key);
    } catch (const std::exception& e) {
        LOKI_LOG(debug, "Error decrypting an onion request: {}", e.what());
        return ProcessCiphertextError::INVALID_CIPHERTEXT;
    }

    LOKI_LOG(debug, "onion request decrypted: (len: {})", plaintext.size());

    const auto parsed = parse_combined_payload(plaintext);

    try {

        const json inner_json = json::parse(parsed.json, nullptr, true);

        /// Kind of unfortunate that we use "headers" (which is empty)
        /// to identify we are the final destination...
        if (inner_json.find("headers") != inner_json.end()) {

            LOKI_LOG(trace, "Found body: <{}>", parsed.ciphertext);

            /// In v2 the body is parsed.ciphertext
            return FinalDesitnationInfo{parsed.ciphertext};
        } else if (inner_json.find("host") != inner_json.end()) {

            const auto& host =
                inner_json.at("host").get_ref<const std::string&>();
            const auto& target =
                inner_json.at("target").get_ref<const std::string&>();
            return RelayToServerInfo{plaintext, host, target};

        } else {
            // We fall back to forwarding a request to the next node
            const auto& dest =
                inner_json.at("destination").get_ref<const std::string&>();
            const auto& ekey =
                inner_json.at("ephemeral_key").get_ref<const std::string&>();

            return RelayToNodeInfo{parsed.ciphertext, ekey, dest};
        }

    } catch (std::exception& e) {
        LOKI_LOG(debug, "Error parsing inner JSON in onion request: {}",
                 e.what());
        return ProcessCiphertextError::INVALID_JSON;
    }
}

static auto gateway_timeout() -> loki::Response {
    return loki::Response{Status::GATEWAY_TIMEOUT, "Request time out"};
}

static auto make_status(std::string_view status) -> loki::Status {

    int code;
    auto res =
        std::from_chars(status.data(), status.data() + status.size(), code);

    if (res.ec == std::errc::invalid_argument ||
        res.ec == std::errc::result_out_of_range) {
        return Status::INTERNAL_SERVER_ERROR;
    }

    switch (code) {

    case 200:
        return Status::OK;
    case 400:
        return Status::BAD_REQUEST;
    case 403:
        return Status::FORBIDDEN;
    case 406:
        return Status::NOT_ACCEPTABLE;
    case 421:
        return Status::MISDIRECTED_REQUEST;
    case 432:
        return Status::INVALID_POW;
    case 500:
        return Status::INTERNAL_SERVER_ERROR;
    case 502:
        return Status::BAD_GATEWAY;
    case 503:
        return Status::SERVICE_UNAVAILABLE;
    case 504:
        return Status::GATEWAY_TIMEOUT;
    default:
        return Status::INTERNAL_SERVER_ERROR;
    }
}

static void relay_to_node(const ServiceNode& service_node,
                          const RelayToNodeInfo& info,
                          std::function<void(loki::Response)> cb, int req_idx,
                          bool v2) {

    const auto& dest = info.next_node;
    const auto& payload = info.ciphertext;
    const auto& ekey = info.ephemeral_key;

    auto dest_node = service_node.find_node_by_ed25519_pk(dest);

    if (!dest_node) {
        auto msg = fmt::format("Next node not found: {}", dest);
        LOKI_LOG(warn, "{}", msg);
        auto res = loki::Response{Status::BAD_GATEWAY, std::move(msg)};
        cb(std::move(res));
        return;
    }

    nlohmann::json req_body;

    req_body["ciphertext"] = payload;
    req_body["ephemeral_key"] = ekey;

    auto on_response = [cb, &service_node](bool success,
                                           std::vector<std::string> data) {
        // Processing the result we got from upstream

        if (!success) {
            LOKI_LOG(debug, "[Onion request] Request time out");
            cb(gateway_timeout());
            return;
        }

        // We only expect a two-part message
        if (data.size() != 2) {
            LOKI_LOG(debug, "[Onion request] Incorrect number of messages: {}",
                     data.size());
            cb(loki::Response{Status::INTERNAL_SERVER_ERROR,
                              "Incorrect number of messages from gateway"});
            return;
        }

        /// We use http status codes (for now)
        if (data[0] != "200") {
            LOKI_LOG(debug, "Onion request relay failed with: {}", data[1]);
        }
        cb(loki::Response{make_status(data[0]), std::move(data[1])});
    };

    LOKI_LOG(debug, "send_onion_to_sn, sn: {} reqidx: {}", *dest_node, req_idx);

    if (v2) {
        service_node.send_onion_to_sn_v2(*dest_node, payload, ekey,
                                         on_response);
    } else {
        service_node.send_onion_to_sn_v1(*dest_node, payload, ekey,
                                         on_response);
    }
}

void RequestHandler::process_onion_req(const std::string& ciphertext,
                                       const std::string& ephem_key,
                                       std::function<void(loki::Response)> cb,
                                       bool v2) {
    if (!service_node_.snode_ready()) {
        auto msg =
            fmt::format("Snode not ready: {}",
                        service_node_.own_address().pubkey_ed25519_hex());
        cb(loki::Response{Status::SERVICE_UNAVAILABLE, std::move(msg)});
        return;
    }

    LOKI_LOG(debug, "process_onion_req, v2: {}", v2);

    static int counter = 0;

    ParsedInfo res;

    if (v2) {
        res =
            process_ciphertext_v2(this->channel_cipher_, ciphertext, ephem_key);
    } else {
        res =
            process_ciphertext_v1(this->channel_cipher_, ciphertext, ephem_key);
    }

    if (const auto info = std::get_if<FinalDesitnationInfo>(&res)) {

        LOKI_LOG(debug, "We are the final destination in the onion request!");

        this->process_onion_exit(
            ephem_key, info->body,
            [this, ephem_key, cb = std::move(cb)](loki::Response res) {
                auto wrapped_res = this->wrap_proxy_response(
                    res, ephem_key, true /* use aes gcm */);
                cb(std::move(wrapped_res));
            });

        return;

    } else if (const auto info = std::get_if<RelayToNodeInfo>(&res)) {

        relay_to_node(this->service_node_, *info, std::move(cb), counter++, v2);

    } else if (const auto info = std::get_if<RelayToServerInfo>(&res)) {
        LOKI_LOG(debug, "We are to forward the request to url: {}{}",
                 info->host, info->target);

        const auto& target = info->target;

        // Forward the request to url but only if it ends in `/lsrpc`
        if ((target.rfind("/lsrpc") == target.size() - 6) &&
            (target.find('?') == std::string::npos)) {
            this->process_onion_to_url(info->host, target, info->payload,
                                       std::move(cb));

        } else {

            auto res = loki::Response{Status::BAD_REQUEST, "Invalid url"};
            auto wrapped_res = this->wrap_proxy_response(res, ephem_key, true);
            cb(std::move(wrapped_res));
        }

    } else if (const auto error = std::get_if<ProcessCiphertextError>(&res)) {
        switch (*error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT: {
            // Should this error be propagated back to the client? (No, if we
            // couldn't decrypt, we probably won't be able to encrypt either.)
            cb(loki::Response{Status::BAD_REQUEST, "Invalid ciphertext"});
            break;
        }
        case ProcessCiphertextError::INVALID_JSON: {
            auto res = loki::Response{Status::BAD_REQUEST, "Invalid json"};

            auto wrapped_res = this->wrap_proxy_response(res, ephem_key, true);

            cb(std::move(wrapped_res));
            break;
        }
        }
    } else {
        LOKI_LOG(error, "UNKNOWN VARIANT");
    }
}

} // namespace loki