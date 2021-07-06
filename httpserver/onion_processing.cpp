#include "channel_encryption.hpp"
#include "http.h"
#include "oxen_logger.h"
#include "service_node.h"
#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>
#include <oxenmq/base64.h>
#include <oxenmq/variant.h>

#include "onion_processing.h"

#include "utils.hpp"
#include "string_utils.hpp"

#include <variant>

using nlohmann::json;

namespace oxen {

ParsedInfo process_inner_request(std::string plaintext) {

    ParsedInfo ret;

    try {
        auto [ciphertext, inner_json] = parse_combined_payload(plaintext);

        /// Kind of unfortunate that we use "headers" (which is empty)
        /// to identify we are the final destination...
        if (inner_json.count("headers")) {
            OXEN_LOG(trace, "Found body: <{}>", ciphertext);
            auto& [body, json, b64] = ret.emplace<FinalDestinationInfo>();
            body = std::move(ciphertext);
            if (auto it = inner_json.find("json"); it != inner_json.end())
                json = it->get<bool>();
            if (auto it = inner_json.find("base64"); it != inner_json.end())
                b64 = it->get<bool>();
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
            auto& [ctext, eph_key, enc_type, next] = ret.emplace<RelayToNodeInfo>();
            ctext = std::move(ciphertext);
            next = ed25519_pubkey::from_hex(
                inner_json.at("destination").get_ref<const std::string&>());
            eph_key = x25519_pubkey::from_hex(
                inner_json.at("ephemeral_key").get_ref<const std::string&>());
            if (auto it = inner_json.find("enc_type"); it != inner_json.end())
                enc_type = parse_enc_type(it->get_ref<const std::string&>());
            else
                enc_type = EncryptType::aes_gcm;
        }
    } catch (const std::exception& e) {
        OXEN_LOG(debug, "Error parsing inner JSON in onion request: {}",
                 e.what());
        ret = ProcessCiphertextError::INVALID_JSON;
    }

    return ret;
}

ParsedInfo process_ciphertext_v2(
        const ChannelEncryption& decryptor,
        std::string_view ciphertext,
        const x25519_pubkey& ephem_key,
        EncryptType enc_type) {

    std::optional<std::string> plaintext;

    try {
        plaintext = decryptor.decrypt(enc_type, ciphertext, ephem_key);
    } catch (const std::exception& e) {
        OXEN_LOG(err, "Error decrypting {} bytes onion request using {}: {}",
                ciphertext.size(), enc_type,
                e.what());
    }
    if (!plaintext)
        return ProcessCiphertextError::INVALID_CIPHERTEXT;

    OXEN_LOG(debug, "onion request decrypted: (len: {})", plaintext->size());

    return process_inner_request(std::move(*plaintext));
}

bool is_onion_url_target_allowed(std::string_view target) {
    return
        (util::starts_with(target, "/loki/") || util::starts_with(target, "/oxen/")) &&
        util::ends_with(target, "/lsrpc") &&
        target.find('?') == std::string::npos;
}

/// We are expecting a payload of the following shape:
/// | <4 bytes>: N | <N bytes>: ciphertext | <rest>: json as utf8 |
CiphertextPlusJson parse_combined_payload(std::string_view payload) {

    OXEN_LOG(trace, "Parsing payload of length: {}", payload.size());

    /// First 4 bytes as number
    if (payload.size() < 4) {
        OXEN_LOG(warn, "Unexpected payload size; expected ciphertext size");
        throw std::runtime_error{"Unexpected payload size; expected ciphertext size"};
    }

    uint32_t n;
    std::memcpy(&n, payload.data(), 4);
    payload.remove_prefix(4);
    boost::endian::little_to_native_inplace(n);
    OXEN_LOG(trace, "Ciphertext length: {}", n);

    if (payload.size() < n) {
        auto msg = fmt::format("Unexpected payload size {}, expected >= {}", payload.size(), n);
        OXEN_LOG(warn, "{}", msg);
        throw std::runtime_error{msg};
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
               R"("["ciphertext": {}, "ephemeral_key": {}, "enc_type": {}, "next_node": {}])",
               d.ciphertext, d.ephemeral_key, d.enc_type, d.next_node);
}

bool operator==(const RelayToNodeInfo& a, const RelayToNodeInfo& b) {
    return std::tie(a.ciphertext, a.ephemeral_key, a.enc_type, a.next_node)
        == std::tie(b.ciphertext, b.ephemeral_key, b.enc_type, b.next_node);
}

} // namespace oxen
