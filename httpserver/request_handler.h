#pragma once

#include <string>
#include <string>
#include "loki_common.h"

// TODO: can I avoid including this in the header?
#include "../external/json.hpp"

// TODO: move ChannelEncryption to ::loki
template <typename T>
class ChannelEncryption;

namespace loki {

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
};

enum class ContentType {
    plaintext,
    json,
};

namespace ss_client {

enum class ReqMethod {
    DATA, // Database entries
    PROXY_EXIT, // A session client request coming through a proxy
    ONION_REQUEST,
};

class Request {

public:
    std::string body;
    // Might change this to a vector later
    std::map<std::string, std::string> headers;
};

};

class Response {

    Status status_;
    std::string message_;
    ContentType content_type_;

  public:
    Response(Status s, std::string m, ContentType ct = ContentType::plaintext)
        : status_(s), message_(std::move(m)), content_type_(ct) {}

    const std::string& message() const { return message_; }
    Status status() const { return status_; }
    ContentType content_type() const { return content_type_; }
};

std::string to_string(const Response& res);

class RequestHandler {

    ServiceNode& service_node_;
    const ChannelEncryption<std::string>& channel_cipher_;

    // Wrap response `res` to an intermediate node
    Response wrap_proxy_response(const Response& res,
                                 const std::string& client_key) const;

    // Return the correct swarm for `pubKey`
    Response handle_wrong_swarm(const user_pubkey_t& pubKey);

    // ===== Session Client Requests =====

    // Similar to `handle_wrong_swarm`; but used when the swarm is requested explicitly
    Response process_snodes_by_pk(const nlohmann::json& params) const;

    // Save the message and relay the swarm
    Response process_store(const nlohmann::json& params);

    // Query the database and return requested messages
    Response process_retrieve(const nlohmann::json& params);

    Response process_onion_exit(const std::string& eph_key,
                                const std::string& payload);

    // ===================================


public:

    RequestHandler(ServiceNode& sn, const ChannelEncryption<std::string>& ce);

    // Process all Session client requests
    Response process_client_req(const std::string& req_json);

    // Test only: retrieve all db entires
    Response process_retrieve_all();

    // Handle a Session client reqeust sent via SN proxy
    Response process_proxy_exit(const std::string& client_key,
                                const std::string& payload);

    // The result will arrive asynchronously, so it needs a callback handler
    void process_onion_req(const std::string& ciphertext,
                           const std::string& ephem_key,
                           std::function<void(loki::Response)> cb);
};

}