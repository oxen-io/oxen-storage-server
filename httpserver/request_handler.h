#pragma once

#include "oxen_common.h"
#include "oxend_key.h"
#include <string>
#include <string_view>

#include <boost/asio.hpp>

#include <nlohmann/json_fwd.hpp>

namespace oxen {

class ChannelEncryption;
enum struct EncryptType;
class ServiceNode;

enum class Status {
    OK = 200,
    BAD_REQUEST = 400,
    FORBIDDEN = 403,
    NOT_ACCEPTABLE = 406,
    MISDIRECTED_REQUEST = 421,
    INVALID_POW = 432, // unassigned http code
    SERVICE_UNAVAILABLE = 503,
    INTERNAL_SERVER_ERROR = 500,
    BAD_GATEWAY = 502,
    GATEWAY_TIMEOUT = 504,
};

enum class ContentType {
    plaintext,
    json,
};

namespace ss_client {

enum class ReqMethod {
    DATA,       // Database entries
    PROXY_EXIT, // A session client request coming through a proxy
    ONION_REQUEST,
};

class Request {

  public:
    std::string body;
    // Might change this to a vector later
    std::map<std::string, std::string> headers;
};

}; // namespace ss_client

class Response {

    Status status_;
    std::string message_;
    ContentType content_type_;

  public:
    Response(Status s, std::string m, ContentType ct = ContentType::plaintext)
        : status_(s), message_(std::move(m)), content_type_(ct) {}

    const std::string& message() const & { return message_; }
    std::string&& message() && { return std::move(message_); }

    Status status() const { return status_; }
    ContentType content_type() const { return content_type_; }
};

std::string to_string(const Response& res);

/// Compute message's hash based on its constituents.
std::string computeMessageHash(const std::string& timestamp,
                               const std::string& ttl,
                               const std::string& recipient,
                               const std::string& data);

class RequestHandler {

    boost::asio::io_context& ioc_;
    ServiceNode& service_node_;
    const ChannelEncryption& channel_cipher_;

    // Wrap response `res` to an intermediate node
    Response wrap_proxy_response(Response res,
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

    void process_onion_exit(const x25519_pubkey& eph_key,
                            const std::string& payload,
                            std::function<void(oxen::Response)> cb);

    void process_lns_request(std::string name_hash,
                             std::function<void(oxen::Response)> cb);

    // ===================================

  public:
    RequestHandler(boost::asio::io_context& ioc, ServiceNode& sn,
                   const ChannelEncryption& ce);

    // Process all Session client requests
    void process_client_req(const std::string& req_json,
                            std::function<void(oxen::Response)> cb);

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
                               std::function<void(oxen::Response)> cb);

    // Test only: retrieve all db entires
    Response process_retrieve_all();

    // Handle a Session client reqeust sent via SN proxy
    void process_proxy_exit(
            const x25519_pubkey& client_key,
            std::string_view payload,
            std::function<void(oxen::Response)> cb);

    void process_onion_to_url(const std::string& protocol,
                              const std::string& host, const uint16_t port,
                              const std::string& target,
                              const std::string& payload,
                              std::function<void(oxen::Response)> cb);

    // The result will arrive asynchronously, so it needs a callback handler
    void process_onion_req(std::string_view ciphertext,
                           const x25519_pubkey& ephem_key,
                           std::function<void(oxen::Response)> cb,
                           // Whether to use the new v2 protocol
                           bool v2 = false);
};
} // namespace oxen
