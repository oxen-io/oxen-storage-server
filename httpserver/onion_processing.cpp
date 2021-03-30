#include "channel_encryption.hpp"
#include "oxen_logger.h"
#include "request_handler.h"
#include "service_node.h"
#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>
#include <oxenmq/base64.h>

#include "onion_processing.h"

#include "utils.hpp"

#include <charconv>
#include <variant>

using nlohmann::json;

namespace oxen {

auto process_inner_request(const CiphertextPlusJson& parsed,
                           std::string plaintext) -> ParsedInfo {

    try {

        const json inner_json = json::parse(parsed.json, nullptr, true);

        /// Kind of unfortunate that we use "headers" (which is empty)
        /// to identify we are the final destination...
        if (inner_json.find("headers") != inner_json.end()) {

            OXEN_LOG(trace, "Found body: <{}>", parsed.ciphertext);

            /// In v2 the body is parsed.ciphertext
            return FinalDestinationInfo{parsed.ciphertext};
        } else if (inner_json.find("host") != inner_json.end()) {

            const auto& host =
                inner_json.at("host").get_ref<const std::string&>();
            const auto& target =
                inner_json.at("target").get_ref<const std::string&>();
            // NOTE: We used to assume https on port 443. Now the client
            // can specify the port and the protocol in the request.
            std::string protocol = "https";
            uint16_t port = 443;

            if (inner_json.find("port") != inner_json.end()) {
                port = inner_json.at("port").get<uint16_t>();
            }

            if (inner_json.find("protocol") != inner_json.end()) {
                protocol =
                    inner_json.at("protocol").get_ref<const std::string&>();
            }

            return RelayToServerInfo{plaintext, host, port, protocol, target};

        } else {
            // We fall back to forwarding a request to the next node
            const auto& dest =
                inner_json.at("destination").get_ref<const std::string&>();
            const auto& ekey =
                inner_json.at("ephemeral_key").get_ref<const std::string&>();

            return RelayToNodeInfo{parsed.ciphertext, ekey, dest};
        }

    } catch (std::exception& e) {
        OXEN_LOG(debug, "Error parsing inner JSON in onion request: {}",
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
        OXEN_LOG(debug, "Error decrypting an onion request: {}", e.what());
        return ProcessCiphertextError::INVALID_CIPHERTEXT;
    }

    OXEN_LOG(debug, "onion request decrypted: (len: {})", plaintext.size());

    const auto parsed = parse_combined_payload(plaintext);

    return process_inner_request(parsed, plaintext);
}

static auto gateway_timeout() -> oxen::Response {
    return oxen::Response{Status::GATEWAY_TIMEOUT, "Request time out"};
}

static auto make_status(std::string_view status) -> oxen::Status {

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
                          std::function<void(oxen::Response)> cb, int req_idx,
                          bool v2) {

    const auto& dest = info.next_node;
    const auto& payload = info.ciphertext;
    const auto& ekey = info.ephemeral_key;

    auto dest_node = service_node.find_node_by_ed25519_pk(dest);

    if (!dest_node) {
        auto msg = fmt::format("Next node not found: {}", dest);
        OXEN_LOG(warn, "{}", msg);
        auto res = oxen::Response{Status::BAD_GATEWAY, std::move(msg)};
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
            OXEN_LOG(debug, "[Onion request] Request time out");
            cb(gateway_timeout());
            return;
        }

        // We only expect a two-part message
        if (data.size() != 2) {
            OXEN_LOG(debug, "[Onion request] Incorrect number of messages: {}",
                     data.size());
            cb(oxen::Response{Status::INTERNAL_SERVER_ERROR,
                              "Incorrect number of messages from gateway"});
            return;
        }

        /// We use http status codes (for now)
        if (data[0] != "200") {
            OXEN_LOG(debug, "Onion request relay failed with: {}", data[1]);
        }
        cb(oxen::Response{make_status(data[0]), std::move(data[1])});
    };

    OXEN_LOG(debug, "send_onion_to_sn, sn: {} reqidx: {}", *dest_node, req_idx);

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
                                       std::function<void(oxen::Response)> cb,
                                       bool v2) {
    if (!service_node_.snode_ready()) {
        auto msg =
            fmt::format("Snode not ready: {}",
                        service_node_.own_address().pubkey_ed25519_hex());
        cb(oxen::Response{Status::SERVICE_UNAVAILABLE, std::move(msg)});
        return;
    }

    OXEN_LOG(debug, "process_onion_req, v2: {}", v2);

    static int counter = 0;

    ParsedInfo res;

    if (v2) {
        res =
            process_ciphertext_v2(this->channel_cipher_, ciphertext, ephem_key);
    } else {
        OXEN_LOG(warn, "onion requests v1 are no longer supported");
        cb(oxen::Response{Status::BAD_REQUEST, "onion requests v2 not supported"});
        return;
    }

    if (const auto info = std::get_if<FinalDestinationInfo>(&res)) {

        OXEN_LOG(debug, "We are the final destination in the onion request!");

        this->process_onion_exit(
            ephem_key, info->body,
            [this, ephem_key, cb = std::move(cb)](oxen::Response res) {
                auto wrapped_res = this->wrap_proxy_response(
                    res, ephem_key, true /* use aes gcm */);
                cb(std::move(wrapped_res));
            });

        return;

    } else if (const auto info = std::get_if<RelayToNodeInfo>(&res)) {

        relay_to_node(this->service_node_, *info, std::move(cb), counter++, v2);

    } else if (const auto info = std::get_if<RelayToServerInfo>(&res)) {
        OXEN_LOG(debug, "We are to forward the request to url: {}{}",
                 info->host, info->target);

        const auto& target = info->target;

        // Forward the request to url but only if it ends in `/lsrpc`
        if ((util::ends_with(target, "/lsrpc")) &&
            (target.find('?') == std::string::npos)) {
            this->process_onion_to_url(info->protocol, info->host, info->port,
                                       target, info->payload, std::move(cb));

        } else {

            auto res = oxen::Response{Status::BAD_REQUEST, "Invalid url"};
            auto wrapped_res = this->wrap_proxy_response(res, ephem_key, true);
            cb(std::move(wrapped_res));
        }

    } else if (const auto error = std::get_if<ProcessCiphertextError>(&res)) {
        switch (*error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT: {
            // Should this error be propagated back to the client? (No, if we
            // couldn't decrypt, we probably won't be able to encrypt either.)
            cb(oxen::Response{Status::BAD_REQUEST, "Invalid ciphertext"});
            break;
        }
        case ProcessCiphertextError::INVALID_JSON: {
            auto res = oxen::Response{Status::BAD_REQUEST, "Invalid json"};

            auto wrapped_res = this->wrap_proxy_response(res, ephem_key, true);

            cb(std::move(wrapped_res));
            break;
        }
        }
    } else {
        OXEN_LOG(error, "UNKNOWN VARIANT");
    }
}

/// We are expecting a payload of the following shape:
/// | <4 bytes>: N | <N bytes>: ciphertext | <rest>: json as utf8 |
auto parse_combined_payload(const std::string& payload) -> CiphertextPlusJson {

    OXEN_LOG(trace, "Parsing payload of length: {}", payload.size());

    auto it = payload.begin();

    /// First 4 bytes as number
    if (payload.size() < 4) {
        OXEN_LOG(warn, "Unexpected payload size");
        throw std::exception();
    }

    uint32_t n;
    std::memcpy(&n, payload.data(), sizeof(uint32_t));
    boost::endian::little_to_native_inplace(n);

    OXEN_LOG(trace, "Ciphertext length: {}", n);

    if (payload.size() < 4 + n) {
        OXEN_LOG(warn, "Unexpected payload size");
        throw std::exception();
    }

    it += sizeof(uint32_t);

    const auto ciphertext = std::string(it, it + n);

    OXEN_LOG(debug, "ciphertext length: {}", ciphertext.size());

    const auto json_blob = std::string(it + n, payload.end());

    OXEN_LOG(debug, "json blob: (len: {})", json_blob.size());

    return CiphertextPlusJson{ciphertext, json_blob};
}

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& d) {
    return os << fmt::format("[\"body\": {}]", d.body);
}

bool operator==(const FinalDestinationInfo& lhs,
                const FinalDestinationInfo& rhs) {
    return lhs.body == rhs.body;
}

std::ostream& operator<<(std::ostream& os, const RelayToServerInfo& d) {
    return os << fmt::format("[\"protocol\": {}, \"host\": {}, \"port\": {}, "
                             "\"target\": {}, \"payload\": {}]",
                             d.protocol, d.host, d.port, d.target, d.payload);
}

bool operator==(const RelayToServerInfo& lhs, const RelayToServerInfo& rhs) {
    return (lhs.protocol == rhs.protocol) && (lhs.host == rhs.host) &&
           (lhs.port == rhs.port) && (lhs.target == rhs.target) &&
           (lhs.payload == rhs.payload);
}

std::ostream& operator<<(std::ostream& os, const RelayToNodeInfo& d) {
    return os << fmt::format(
               "[\"ciphertext\": {}, \"ephemeral_key\": {}, \"next_node\": {}]",
               d.ciphertext, d.ephemeral_key, d.next_node);
}

bool operator==(const RelayToNodeInfo& lhs, const RelayToNodeInfo& rhs) {
    return (lhs.ciphertext == rhs.ciphertext) &&
           (lhs.ephemeral_key == rhs.ephemeral_key) &&
           (lhs.next_node == lhs.next_node);
}

} // namespace oxen
