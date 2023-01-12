#pragma once

#include <oxenss/crypto/channel_encryption.hpp>
#include "client_rpc_endpoints.h"
#include "onion_processing.h"
#include <oxenc/bt_serialize.h>
#include <oxenss/crypto/keys.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/server/utils.h>
#include <oxenss/utils/time.hpp>

#include <chrono>
#include <forward_list>
#include <future>
#include <string>
#include <string_view>
#include <type_traits>

#include <nlohmann/json_fwd.hpp>
#include <variant>

namespace oxen::rpc {

// When a storage test returns a "retry" response, we retry again after this interval:
inline constexpr auto TEST_RETRY_INTERVAL = 50ms;

// If a storage test is still returning "retry" after this long since the initial request then
// we give up and send an error response back to the requestor:
inline constexpr auto TEST_RETRY_PERIOD = 55s;

// Minimum and maximum TTL permitted for storing a new, public message
inline constexpr auto TTL_MINIMUM = 10s;
inline constexpr auto TTL_MAXIMUM = 14 * 24h;

// For messages in a user's control (i.e. new messages in private namespaces, or updating TTLs of
// existing public or private namespace messages) we allow a longer TTL (starting at HF19.3).
inline constexpr auto TTL_MAXIMUM_PRIVATE = 30 * 24h;

// Tolerance for store requests: we don't allow stores with a timestamp more than this into the
// future, and don't allow stores with an expiry in the past by more than this amount.
inline constexpr auto STORE_TOLERANCE = 10s;

// Tolerance for timestamp-dependent, signed requests (such as `delete_all`); we accept the
// initial request if within SIGNATURE_TOLERANCE of now, and accept a recursive request if
// within SIGNATURE_TOLERANCE_FORWARDED (generally slightly larger to account for swarm
// forwarding latency).
inline constexpr auto SIGNATURE_TOLERANCE = 60s;
inline constexpr auto SIGNATURE_TOLERANCE_FORWARDED = 70s;

// Maximum retrieve size (in bytes).  We have to be quite conversative here because there are
// several ways with multiple layers of base64 encoding that can occur: first, for json, the body
// gets base64 encoded, but then onion requests (by default) also b64 encode the encrypted payload,
// so we might have double base64 encoding.  We include the first b64 encoding overhead in our size
// calculation, but not the second, and so this value is reduced to accomodate it.
//
// The maximum network message size is 10MiB, which means the max before b64 encoding is 7.5MiB
// (7864320).  We allow for some respoinse overhead, which lands us on this effective maximum:
inline constexpr int RETRIEVE_MAX_SIZE = 7'800'000;

// Maximum subrequests that can be stuffed into a single batch request
inline constexpr size_t BATCH_REQUEST_MAX = 20;

// Simpler wrapper that works for most of our responses
struct Response {
    http::response_code status = http::OK;
    std::variant<std::string, std::string_view, nlohmann::json> body;
    std::vector<std::pair<std::string, std::string>> headers;

    Response() = default;
    Response(
            http::response_code status,
            std::variant<std::string, std::string_view, nlohmann::json> body = ""sv,
            std::vector<std::pair<std::string, std::string>> headers = {}) :
            status{status}, body{std::move(body)}, headers{std::move(headers)} {}
};

// Views the string or string_view body inside a Response.  Should only be called when the body
// has already been verified to not contain a json object.
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
    // detail::to_hashable takes either an integral type, system_clock::time_point, or a string
    // type and converts it to a string_view by writing an integer value (using std::to_chars)
    // into the buffer space (which should be at least 20 bytes), and returning a string_view
    // into the written buffer space.  For strings/string_views the string_view is returned
    // directly from the argument. system_clock::time_points are converted into integral
    // milliseconds since epoch then treated as an integer value.
    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    std::string_view to_hashable(const T& val, char*& buffer) {
        auto [p, ec] = std::to_chars(buffer, buffer + 20, val);
        std::string_view s(buffer, p - buffer);
        buffer = p;
        return s;
    }
    inline std::string_view to_hashable(
            const std::chrono::system_clock::time_point& val, char*& buffer) {
        return to_hashable(to_epoch_ms(val), buffer);
    }
    template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
    std::string_view to_hashable(const T& value, char*&) {
        return value;
    }

}  // namespace detail

/// Compute a hash from the given strings, concatenated together.
std::string compute_hash_blake2b_b64(std::vector<std::string_view> parts);

/// Computes a message hash based on its constituent parts.  Takes a function (which accepts a
/// container of string_views) and any number of std::string, std::string_view, system_clock
/// values, or integer values.  Strings are concatenated; integers are converted to strings via
/// std::to_chars; clock values are treated as integer milliseconds-since-unix-epoch values.
template <typename Func, typename... T>
std::string compute_hash(Func hasher, const T&... args) {
    // Allocate a buffer of 20 bytes per integral value (which is the largest the any integral
    // value can be when stringified).
    std::array<
            char,
            (0 + ... +
             (std::is_integral_v<T> || std::is_same_v<T, std::chrono::system_clock::time_point>
                      ? 20
                      : 0))>
            buffer;
    auto* b = buffer.data();
    return hasher({detail::to_hashable(args, b)...});
}

/// Computes a message hash using blake2b hash of various messages attributes.
std::string computeMessageHash(
        std::chrono::system_clock::time_point timestamp,
        std::chrono::system_clock::time_point expiry,
        const user_pubkey_t& pubkey,
        namespace_id ns,
        std::string_view data);

struct OnionRequestMetadata {
    crypto::x25519_pubkey ephem_key;
    std::function<void(Response)> cb;
    int hop_no = 0;
    crypto::EncryptType enc_type = crypto::EncryptType::aes_gcm;
};

class RequestHandler {

    snode::ServiceNode& service_node_;
    const crypto::ChannelEncryption& channel_cipher_;
    const crypto::ed25519_seckey ed25519_sk_;

    std::forward_list<std::future<void>> pending_proxy_requests_;

    // Wrap response `res` to an intermediate node
    Response wrap_proxy_response(
            Response res,
            const crypto::x25519_pubkey& client_key,
            crypto::EncryptType enc_type,
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
    RequestHandler(
            snode::ServiceNode& sn,
            const crypto::ChannelEncryption& ce,
            crypto::ed25519_seckey ed_sk);

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
    void process_client_req(rpc::get_expiries&&, std::function<void(Response)> cb);
    void process_client_req(rpc::batch&&, std::function<void(Response)> cb);
    void process_client_req(rpc::sequence&&, std::function<void(Response)> cb);
    void process_client_req(rpc::ifelse&&, std::function<void(Response)> cb);
    void process_client_req(rpc::revoke_subkey&& req, std::function<void(Response)> cb);

    struct rpc_handler {
        std::function<client_request(std::variant<nlohmann::json, oxenc::bt_dict_consumer> params)>
                load_req;
        std::function<void(RequestHandler&, nlohmann::json, std::function<void(Response)>)>
                http_json;
        std::function<void(
                RequestHandler&,
                std::string_view params,
                bool recurse,
                std::function<void(Response)>)>
                omq;
    };

    using rpc_map = std::unordered_map<std::string_view, rpc_handler>;

    static const rpc_map client_rpc_endpoints;

    // Process a client request taking encoded json to be parsed containing something like
    // `{"method": "abc", "params": {"some_arg": 1}}`, dispatching to the appropriate request
    // handler.
    void process_client_req(std::string_view req_json, std::function<void(Response)> cb);

    // Processes a pre-parsed client request taking the method name ("store", "retrieve", etc.)
    // and the json params object.
    void process_client_req(
            std::string_view method, nlohmann::json params, std::function<void(Response)> cb);

    // Processes a swarm test request; if it succeeds the callback is immediately invoked,
    // otherwise the test is scheduled for retries for some time until it succeeds, fails, or
    // times out, at which point the callback is invoked to return the result.
    void process_storage_test_req(
            uint64_t height,
            crypto::legacy_pubkey tester,
            std::string msg_hash_hex,
            std::function<void(
                    snode::MessageTestStatus, std::string, std::chrono::steady_clock::duration)>
                    callback);

    // Forwards a request to oxend RPC. `params` should contain:
    // - endpoint -- the name of the rpc endpoint; currently allowed are `ons_resolve` and
    // `get_service_nodes`.
    // - params -- optional dict of parameters to pass through to oxend as part of the request
    //
    // See oxen-core/rpc/core_rpc_server_command_defs.h for parameters to these endpoints.
    //
    // Returns (via the response callback) the oxend JSON object on success; on failure returns
    // a failure response with a body of the error string.
    void process_oxend_request(const nlohmann::json& params, std::function<void(Response)> cb);

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

}  // namespace oxen::rpc
