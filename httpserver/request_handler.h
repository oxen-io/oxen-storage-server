#pragma once

#include "channel_encryption.hpp"
#include "http.h"
#include "onion_processing.h"
#include "oxen_common.h"
#include "oxend_key.h"
#include "service_node.h"
#include "string_utils.hpp"
#include <chrono>
#include <forward_list>
#include <future>
#include <string>
#include <string_view>

#include <nlohmann/json_fwd.hpp>

namespace oxen {

constexpr size_t MAX_MESSAGE_BODY = 102400; // 100 KB limit

// When a storage test returns a "retry" response, we retry again after this interval:
inline constexpr auto TEST_RETRY_INTERVAL = 50ms;

// If a storage test is still returning "retry" after this long since the initial request then we
// give up and send an error response back to the requestor:
inline constexpr auto TEST_RETRY_PERIOD = 55s;


// Simpler wrapper that works for most of our responses
struct Response {
    http::response_code status = http::OK;
    std::string body;
    std::string_view content_type = http::plaintext;
    std::vector<std::pair<std::string, std::string>> headers;
};

std::string to_string(const Response& res);

/// Compute message's hash based on its constituents.  The hash is a SHA-512 hash of the
/// concatenated string parts, and can be returned as either bytes (64 bytes) or hex (128 chars)
std::string computeMessageHash(std::vector<std::string_view> parts, bool hex);

// Validates a TTL value to see if it is acceptable.
bool validateTTL(std::chrono::milliseconds ttl);

// Validates a timestamp to see if it is acceptable.  Takes the timestamp and the associated TTL.
bool validateTimestamp(std::chrono::system_clock::time_point timestamp, std::chrono::milliseconds ttl);


struct OnionRequestMetadata {
    x25519_pubkey ephem_key;
    std::function<void(Response)> cb;
    int hop_no = 0;
    EncryptType enc_type = EncryptType::aes_gcm;
};

class RequestHandler {

    ServiceNode& service_node_;
    const ChannelEncryption& channel_cipher_;

    std::forward_list<std::future<void>> pending_proxy_requests_;

    // Wrap response `res` to an intermediate node
    Response wrap_proxy_response(
            Response res,
            const x25519_pubkey& client_key,
            EncryptType enc_type,
            bool json = false,
            bool base64 = true) const;

    // Return the correct swarm for `pubKey`
    Response handle_wrong_swarm(const user_pubkey_t& pubKey);

    // ===== Session Client Requests =====

    // Similar to `handle_wrong_swarm`; but used when the swarm is requested
    // explicitly
    Response process_snodes_by_pk(const nlohmann::json& params) const;

    // Save the message and relay the swarm
    Response process_store(const nlohmann::json& params);

    // Query the database and return requested messages
    Response process_retrieve(const nlohmann::json& params);

    void process_onion_exit(std::string_view payload,
                            std::function<void(Response)> cb);

    // ===================================

  public:
    RequestHandler(ServiceNode& sn, const ChannelEncryption& ce);

    // Process all Session client requests
    void process_client_req(std::string_view req_json,
                            std::function<void(Response)> cb);

    // Processes a swarm test request; if it succeeds the callback is immediately invoked, otherwise
    // the test is scheduled for retries for some time until it succeeds, fails, or times out, at
    // which point the callback is invoked to return the result.
    void process_storage_test_req(
            uint64_t height,
            legacy_pubkey tester,
            std::string msg_hash_hex,
            std::function<void(MessageTestStatus, std::string, std::chrono::steady_clock::duration)> callback);

    // Forwards a request to oxend RPC. `params` should contain:
    // - endpoint -- the name of the rpc endpoint; currently allowed are `ons_resolve` and
    // `get_service_nodes`.
    // - params -- optional dict of parameters to pass through to oxend as part of the request
    //
    // See oxen-core/rpc/core_rpc_server_command_defs.h for parameters to these endpoints.
    //
    // Returns (via the response callback) the oxend JSON object on success; on failure returns
    // a failure response with a body of the error string.
    void process_oxend_request(const nlohmann::json& params,
                               std::function<void(Response)> cb);

    // Test only: retrieve all db entires
    Response process_retrieve_all();

    // Handle a Session client reqeust sent via SN proxy
    void process_proxy_exit(
            const x25519_pubkey& client_key,
            std::string_view payload,
            std::function<void(Response)> cb);

    // The result will arrive asynchronously, so it needs a callback handler
    void process_onion_req(std::string_view ciphertext, OnionRequestMetadata data);

  private:
    void process_onion_req(FinalDestinationInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(RelayToNodeInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(RelayToServerInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(ProcessCiphertextError&& res, OnionRequestMetadata&& data);
};
} // namespace oxen
