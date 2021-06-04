#pragma once

#include "channel_encryption.hpp"
#include "client_rpc_endpoints.h"
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
#include <type_traits>

#include <nlohmann/json_fwd.hpp>
#include <variant>

namespace oxen {

// When a storage test returns a "retry" response, we retry again after this interval:
inline constexpr auto TEST_RETRY_INTERVAL = 50ms;

// If a storage test is still returning "retry" after this long since the initial request then we
// give up and send an error response back to the requestor:
inline constexpr auto TEST_RETRY_PERIOD = 55s;

// Minimum and maximum TTL permitted for a message storage request
inline constexpr auto TTL_MINIMUM = 10s;
inline constexpr auto TTL_MAXIMUM = 14 * 24h;


// Simpler wrapper that works for most of our responses
struct Response {
    http::response_code status = http::OK;
    std::variant<std::string, std::string_view, nlohmann::json> body;
    std::vector<std::pair<std::string, std::string>> headers;
};

// Views the string or string_view body inside a Response.  Should only be called when the body has
// already been verified to not contain a json object.
inline std::string_view view_body(const Response& r) {
    assert(!std::holds_alternative<nlohmann::json>(r.body));
    if (auto* sv = std::get_if<std::string_view>(&r.body))
        return *sv;
    if (auto* s = std::get_if<std::string>(&r.body))
        return *s;
    return "(internal error)"sv;
}

std::string to_string(const Response& res);

namespace detail {

// detail::to_hashable takes either an integral type, system_clock::time_point, or a string type and
// converts it to a string_view by writing an integer value (using std::to_chars) into the buffer
// space, and returning a string_view.  (For strings/string_views the string_view is returned
// directly from the argument).  system_clock::time_points are converted into integral milliseconds
// since epoch then treated as an integer value.
template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
std::string_view to_hashable(const T& val, char*& buffer) {
    auto [p, ec] = std::to_chars(buffer, buffer+20, val);
    std::string_view s(buffer, p-buffer);
    buffer = p;
    return s;
}
inline std::string_view to_hashable(const std::chrono::system_clock::time_point& val, char*& buffer) {
    return to_hashable(std::chrono::duration_cast<std::chrono::milliseconds>(val.time_since_epoch()).count(), buffer);
}
template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
std::string_view to_hashable(const T& value, char*&) {
    return value;
}

}

/// Compute message's hash based on its constituents.  The hash is a SHA-512 hash of the
/// concatenated string parts, encoded in hex.
std::string computeMessageHash(std::vector<std::string_view> parts);

/// Computes a message hash based on its constituent parts.  Takes any number of std::string,
/// std::string_view, milliseconds, or integer values.  Strings are concatenated; integers are
/// converted to strings via std::to_chars; milliseconds are treated as integer values from their
/// `.count()` value.
template <typename... T>
std::string computeMessageHash(const T&... args) {
    // Allocate a buffer of 20 bytes per integral value (which is the largest the any integral value
    // can be when stringified).
    std::array<char, (0 + ... + (std::is_integral_v<T> ||
                std::is_same_v<T, std::chrono::system_clock::time_point> ? 20 : 0))> buffer;
    auto* b = buffer.data();
    return computeMessageHash({detail::to_hashable(args, b)...});
}

// Validates a TTL value to see if it is acceptable.
bool validateTTL(std::chrono::system_clock::duration ttl);

// Validates a timestamp to see if it is acceptable.  Takes the timestamp and the expiry (when using
// a ttl, give expiry as timestamp+ttl).
bool validateTimestamp(std::chrono::system_clock::time_point timestamp, std::chrono::system_clock::time_point expiry);


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

    // ===================================

  public:
    RequestHandler(ServiceNode& sn, const ChannelEncryption& ce);

    // Handlers for parsed client requests
    void process_client_req(rpc::store&& req, std::function<void(Response)> cb);
    void process_client_req(rpc::retrieve&& req, std::function<void(Response)> cb);
    void process_client_req(rpc::get_swarm&& req, std::function<void(Response)> cb);
    void process_client_req(rpc::oxend_request&& req, std::function<void(Response)> cb);
    void process_client_req(rpc::info&&, std::function<void(Response)> cb);
    void process_client_req(rpc::delete_all&&, std::function<void(Response)> cb);
    void process_client_req(rpc::delete_msgs&&, std::function<void(Response)> cb);
    void process_client_req(rpc::delete_before&&, std::function<void(Response)> cb);
    void process_client_req(rpc::expire_all&&, std::function<void(Response)> cb);
    void process_client_req(rpc::expire_msgs&&, std::function<void(Response)> cb);

    using rpc_map = std::unordered_map<
        std::string_view,
        std::function<void(RequestHandler&, const nlohmann::json&, std::function<void(Response)>)>
    >;
    static const rpc_map client_rpc_endpoints;

    // Process a client request taking encoded json to be parsed containing something like
    // `{"method": "abc", "params": {"some_arg": 1}}`, dispatching to the appropriate request
    // handler.
    void process_client_req(std::string_view req_json, std::function<void(Response)> cb);

    // Processes a pre-parsed client request taking the method name ("store", "retrieve", etc.) and
    // the json params object.
    void process_client_req(
            std::string_view method,
            nlohmann::json params,
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

    // The result will arrive asynchronously, so it needs a callback handler
    void process_onion_req(std::string_view ciphertext, OnionRequestMetadata data);

  private:
    void process_onion_req(FinalDestinationInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(RelayToNodeInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(RelayToServerInfo&& res, OnionRequestMetadata&& data);
    void process_onion_req(ProcessCiphertextError&& res, OnionRequestMetadata&& data);
};

} // namespace oxen
