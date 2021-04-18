#pragma once

#include <nlohmann/json_fwd.hpp>
#include <string>
#include <variant>
#include "oxend_key.h"

namespace oxen {

using CiphertextPlusJson = std::pair<std::string, nlohmann::json>;

/// The request is to be forwarded to another SS node
struct RelayToNodeInfo {
    /// Inner ciphertext for next node
    std::string ciphertext;
    // Key to be forwarded to next node for decryption
    std::string ephemeral_key;
    // Next node's ed25519 key
    ed25519_pubkey next_node;
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
    std::string body;
};

std::ostream& operator<<(std::ostream& os, const FinalDestinationInfo& p);

bool operator==(const FinalDestinationInfo& lhs,
                const FinalDestinationInfo& rhs);

enum class ProcessCiphertextError {
    INVALID_CIPHERTEXT,
    INVALID_JSON,
};

using ParsedInfo = std::variant<RelayToNodeInfo, RelayToServerInfo,
                                FinalDestinationInfo, ProcessCiphertextError>;

auto parse_combined_payload(std::string_view payload) -> CiphertextPlusJson;

auto process_inner_request(std::string plaintext) -> ParsedInfo;

bool is_server_url_allowed(std::string_view url);

} // namespace oxen
