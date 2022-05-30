#pragma once

#include "oxenss/crypto/channel_encryption.hpp"
#include "oxenss/crypto/keys.h"
#include <nlohmann/json_fwd.hpp>
#include <string>
#include <variant>

namespace oxen::rpc {

// Maximum onion request hops we'll accept before we return an error; this is deliberately
// larger than we actually use so that the client can choose to obscure hop positioning by
// starting at somewhere higher than 0.
inline constexpr int MAX_ONION_HOPS = 15;

using CiphertextPlusJson = std::pair<std::string, nlohmann::json>;

/// The request is to be forwarded to another SS node
struct RelayToNodeInfo {
    /// Inner ciphertext for next node
    std::string ciphertext;
    // Key to be forwarded to next node for decryption
    crypto::x25519_pubkey ephemeral_key;
    // The encryption type with which this request was encoded
    crypto::EncryptType enc_type;
    // Next node's ed25519 key
    crypto::ed25519_pubkey next_node;
};

std::ostream& operator<<(std::ostream& os, const RelayToNodeInfo& p);

bool operator==(const RelayToNodeInfo& lhs, const RelayToNodeInfo& rhs);

/// The request is to be forwarded to some non-SS server
/// that supports our protocol (e.g. Session File Server)
struct RelayToServerInfo {
    // Result of decryption (intact)
    std::string payload;
    // Server's address
    std::string host;
    // Server's port
    uint16_t port;
    // Http or Https (TODO: use enum)
    std::string protocol;
    // Request's target
    std::string target;
};

std::ostream& operator<<(std::ostream& os, const RelayToServerInfo& p);

bool operator==(const RelayToServerInfo& lhs, const RelayToServerInfo& rhs);

/// We are the final destination for this request
struct FinalDestinationInfo {
    // Request body
    std::string body;

    // If true, and the response has a content type indicating json, then embed the "body" value
    // as a direct json value rather than encapsulating it as a json string.  For example, when
    // false (the default for backwards compatibility) a json response of {"hi": "123"} would
    // get returned as:
    //
    //     {"body":"{\"hi\":\"123\"},"status":200}  // json=false
    //     {"body":{"hi":"123"},"status":200}       // json=true
    //
    // Note that this json isn't actually parsed and so this can result in invalid json if the
    // supposed-json inner value is not actually json.
    bool json = false;

    // If true (which is the default for backwards compatibility) then encode the encrypted
    // response as base64; if false return the encrypted response as-is.
    bool base64 = true;
};

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& p);

bool operator==(const FinalDestinationInfo& lhs, const FinalDestinationInfo& rhs);

enum class ProcessCiphertextError {
    INVALID_CIPHERTEXT,
    INVALID_JSON,
};

using ParsedInfo = std::
        variant<RelayToNodeInfo, RelayToServerInfo, FinalDestinationInfo, ProcessCiphertextError>;

ParsedInfo process_ciphertext_v2(
        const crypto::ChannelEncryption& decryptor,
        std::string_view ciphertext,
        const crypto::x25519_pubkey& ephem_key,
        crypto::EncryptType enc_type);

CiphertextPlusJson parse_combined_payload(std::string_view payload);

ParsedInfo process_inner_request(std::string plaintext);

// Returns true if `target` is a permitted target for proxying http/https requests through an
// onion request.  Requires that the target start with /oxen/, end with /lsrpc, and does not
// contain a query string.
bool is_onion_url_target_allowed(std::string_view uri);

}  // namespace oxen::rpc
