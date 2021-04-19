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

auto process_inner_request(std::string plaintext) -> ParsedInfo {

    ParsedInfo ret;

    try {
        auto [ciphertext, inner_json] = parse_combined_payload(plaintext);

        /// Kind of unfortunate that we use "headers" (which is empty)
        /// to identify we are the final destination...
        if (inner_json.count("headers")) {
            OXEN_LOG(trace, "Found body: <{}>", ciphertext);
            ret.emplace<FinalDestinationInfo>().body = std::move(ciphertext);
        } else if (auto it = inner_json.find("host"); it != inner_json.end()) {
            auto& [payload, host, port, protocol, target] = ret.emplace<RelayToServerInfo>();
            payload = std::move(plaintext);
            host = it->get<std::string>();
            target = inner_json.at("target").get<std::string>();

            if (auto p = inner_json.find("port"); p != inner_json.end())
                port = p->get<uint16_t>();
            else
                port = 443;

            if (auto p = inner_json.find("protocol"); p != inner_json.end())
                protocol = p->get<std::string>();
            else
                protocol = "https";
        } else {
            auto& [ctext, eph_key, next] = ret.emplace<RelayToNodeInfo>();
            ctext = std::move(ciphertext);
            next = ed25519_pubkey::from_hex(
                inner_json.at("destination").get_ref<const std::string&>());
            eph_key = inner_json.at("ephemeral_key").get<std::string>();
        }
    } catch (std::exception& e) {
        OXEN_LOG(debug, "Error parsing inner JSON in onion request: {}",
                 e.what());
        ret = ProcessCiphertextError::INVALID_JSON;
    }

    return ret;
}

static auto
process_ciphertext_v2(const ChannelEncryption& decryptor,
                      std::string_view ciphertext,
                      const x25519_pubkey& ephem_key) -> ParsedInfo {
    std::optional<std::string> plaintext;

    try {
        plaintext = decryptor.decrypt(EncryptType::aes_gcm, ciphertext, ephem_key);
    } catch (const std::exception& e) {
        OXEN_LOG(debug, "Error decrypting an onion request: {}", e.what());
    }
    if (!plaintext)
        return ProcessCiphertextError::INVALID_CIPHERTEXT;

    OXEN_LOG(debug, "onion request decrypted: (len: {})", plaintext->size());

    return process_inner_request(std::move(*plaintext));
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
                          std::function<void(oxen::Response)> cb,
                          bool v2) {

    const auto& [payload, ekey, dest] = info;

    auto dest_node = service_node.find_node(dest);
    if (!dest_node) {
        auto msg = fmt::format("Next node not found: {}", dest);
        OXEN_LOG(warn, "{}", msg);
        cb({Status::BAD_GATEWAY, std::move(msg)});
        return;
    }


    auto on_response = [cb=std::move(cb)](bool success,
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

    OXEN_LOG(debug, "send_onion_to_sn, sn: {}", dest_node->pubkey_legacy);

    if (v2) {
        service_node.send_onion_to_sn_v2(*dest_node, payload, ekey,
                                         on_response);
    } else {
        service_node.send_onion_to_sn_v1(*dest_node, payload, ekey,
                                         on_response);
    }
}

bool is_server_url_allowed(std::string_view url) {
    return (util::starts_with(url, "/loki/") ||
            util::starts_with(url, "/oxen/")) &&
           util::ends_with(url, "/lsrpc") &&
           (url.find('?') == std::string::npos);
}

// FIXME: why is this method definition *here* instead of request_handler.cpp?
void RequestHandler::process_onion_req(std::string_view ciphertext,
                                       const x25519_pubkey& ephem_key,
                                       std::function<void(oxen::Response)> cb,
                                       bool v2) {
    if (!service_node_.snode_ready()) {
        auto msg =
            fmt::format("Snode not ready: {}",
                        service_node_.own_address().pubkey_ed25519);
        cb(oxen::Response{Status::SERVICE_UNAVAILABLE, std::move(msg)});
        return;
    }

    OXEN_LOG(debug, "process_onion_req, v2: {}", v2);

    if (!v2) {
        OXEN_LOG(warn, "onion requests v1 are no longer supported");
        cb(oxen::Response{Status::BAD_REQUEST,
                          "onion requests v1 not supported"});
        return;
    }

    ParsedInfo res = process_ciphertext_v2(channel_cipher_, ciphertext, ephem_key);

    if (const auto info = std::get_if<FinalDestinationInfo>(&res)) {

        OXEN_LOG(debug, "We are the final destination in the onion request!");

        this->process_onion_exit(
            ephem_key, info->body,
            [this, ephem_key, cb = std::move(cb)](oxen::Response res) {
                cb(wrap_proxy_response(res, ephem_key, EncryptType::aes_gcm));
            });

        return;

    } else if (const auto info = std::get_if<RelayToNodeInfo>(&res)) {

        relay_to_node(this->service_node_, *info, std::move(cb), v2);

    } else if (const auto info = std::get_if<RelayToServerInfo>(&res)) {
        OXEN_LOG(debug, "We are to forward the request to url: {}{}",
                 info->host, info->target);

        const auto& target = info->target;

        // Forward the request to url but only if it ends in `/lsrpc`
        if (is_server_url_allowed(target)) {
            this->process_onion_to_url(info->protocol, info->host, info->port,
                                       target, info->payload, std::move(cb));

        } else {
            cb(wrap_proxy_response({Status::BAD_REQUEST, "Invalid url"},
                    ephem_key, EncryptType::aes_gcm));
        }

    } else if (const auto error = std::get_if<ProcessCiphertextError>(&res)) {
        switch (*error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT: {
            // Should this error be propagated back to the client? (No, if we
            // couldn't decrypt, we probably won't be able to encrypt either.)
            cb({Status::BAD_REQUEST, "Invalid ciphertext"});
            break;
        }
        case ProcessCiphertextError::INVALID_JSON: {
            cb(wrap_proxy_response({Status::BAD_REQUEST, "Invalid json"},
                    ephem_key, EncryptType::aes_gcm));
            break;
        }
        }
    } else {
        OXEN_LOG(error, "UNKNOWN VARIANT");
    }
}

/// We are expecting a payload of the following shape:
/// | <4 bytes>: N | <N bytes>: ciphertext | <rest>: json as utf8 |
auto parse_combined_payload(std::string_view payload) -> CiphertextPlusJson {

    OXEN_LOG(trace, "Parsing payload of length: {}", payload.size());

    /// First 4 bytes as number
    if (payload.size() < 4) {
        OXEN_LOG(warn, "Unexpected payload size");
        throw std::exception();
    }

    uint32_t n;
    std::memcpy(&n, payload.data(), sizeof(uint32_t));
    boost::endian::little_to_native_inplace(n);
    OXEN_LOG(trace, "Ciphertext length: {}", n);

    payload.remove_prefix(sizeof(uint32_t));

    if (payload.size() < n) {
        OXEN_LOG(warn, "Unexpected payload size");
        throw std::runtime_error{"Unexpected payload size"};
    }

    CiphertextPlusJson result;
    auto& [ciphertext, json] = result;

    ciphertext = payload.substr(0, n);
    OXEN_LOG(debug, "ciphertext length: {}", ciphertext.size());
    payload.remove_prefix(ciphertext.size());

    json = json::parse(payload);

    return result;
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

bool operator==(const RelayToNodeInfo& a, const RelayToNodeInfo& b) {
    return std::tie(a.ciphertext, a.ephemeral_key, a.next_node)
        == std::tie(b.ciphertext, b.ephemeral_key, b.next_node);
}

} // namespace oxen
