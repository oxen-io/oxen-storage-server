#pragma once

#include "channel_encryption.hpp"
#include "http.h"
#include "onion_processing.h"
#include "oxen_common.h"
#include "oxend_key.h"
#include "string_utils.hpp"
#include <string>
#include <string_view>

#include <boost/asio.hpp>

#include <nlohmann/json_fwd.hpp>

namespace oxen {

constexpr size_t MAX_MESSAGE_BODY = 102400; // 100 KB limit

class ServiceNode;

namespace ss_client {

enum class ReqMethod {
    DATA,       // Database entries
    PROXY_EXIT, // A session client request coming through a proxy
    ONION_REQUEST,
};

}; // namespace ss_client

// Simpler wrappers that work for most of our requests
struct Request {
    std::string body;
    http::headers headers;
    std::string remote_addr;
    std::string uri;
};

struct Response {
    http::response_code status = http::OK;
    std::string body;
    std::string_view content_type = http::plaintext;
    std::vector<std::pair<std::string, std::string>> headers;
};


std::string to_string(const Response& res);

/// Compute message's hash based on its constituents.
std::string computeMessageHash(std::vector<std::string_view> parts, bool hex);

/// Parse a pubkey string value as either base32z (deprecated!), b64, or hex.  Returns a null pk
/// (i.e. operator bool() returns false) and warns on invalid input.
legacy_pubkey parse_pubkey(std::string_view public_key_in);


struct OnionRequestMetadata {
    x25519_pubkey ephem_key;
    std::function<void(Response)> cb;
    int hop_no = 0;
    EncryptType enc_type = EncryptType::aes_gcm;
};

class RequestHandler {

    ServiceNode& service_node_;
    const ChannelEncryption& channel_cipher_;

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

    void process_lns_request(std::string name_hash,
                             std::function<void(Response)> cb);

    // ===================================

  public:
    RequestHandler(ServiceNode& sn, const ChannelEncryption& ce);

    // Process all Session client requests
    void process_client_req(std::string_view req_json,
                            std::function<void(Response)> cb);

    /// Verifies snode pubkey and signature values in a request; returns the sender pubkey on
    /// success or a filled-out error Response if verification fails.
    ///
    /// `prevalidate` - if true, do a "pre-validation": check that the required header values
    /// (pubkey, signature) are present and valid (including verifying that the pubkey is a valid
    /// snode) but don't actually verify the signature against the body (note that this is *not*
    /// signature verification but is used as a pre-check before reading a body to ensure the
    /// required headers are present).
    std::variant<legacy_pubkey, Response> validate_snode_signature(
            const Request& r, bool headers_only = false);

    // Processes a swarm test request
    Response process_storage_test_req(Request r);

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

    void process_onion_to_url(const std::string& protocol,
                              const std::string& host, const uint16_t port,
                              const std::string& target,
                              const std::string& payload,
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
