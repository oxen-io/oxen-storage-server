#include "request_handler.h"
#include "channel_encryption.hpp"
#include "client_rpc_endpoints.h"
#include "http.h"
#include "omq_server.h"
#include "oxen_logger.h"
#include "oxenmq/oxenmq.h"
#include "signature.h"
#include "service_node.h"
#include "string_utils.hpp"
#include "time.hpp"
#include "utils.hpp"
#include "version.h"

#include <chrono>
#include <future>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <type_traits>
#include <variant>

using nlohmann::json;
using namespace std::chrono;

namespace oxen {

// Timeout for onion-request-to-url requests.  Onion requests have a 30s timeout so we choose a
// timeout a bit shorter than that so that we still have a good chance of the error response getting
// back to the client before the entry node's request times out.
inline constexpr auto ONION_URL_TIMEOUT = 25s;

std::string to_string(const Response& res) {

    std::stringstream ss;

    const bool is_json = std::holds_alternative<json>(res.body);
    ss << "Status: " << res.status.first << " " << res.status.second
        << ", Content-Type: " << (is_json ? "application/json" : "text/plain")
        << ", Body: <" << (is_json ? std::get<json>(res.body).dump() : view_body(res)) << ">";

    return ss.str();
}

namespace {

json swarm_to_json(const SwarmInfo& swarm) {

    json snodes_json = json::array();
    for (const auto& sn : swarm.snodes) {
        snodes_json.push_back(json{
                {"address", oxenmq::to_base32z(sn.pubkey_legacy.view()) + ".snode"}, // Deprecated, use pubkey_legacy instead
                {"pubkey_legacy", sn.pubkey_legacy.hex()},
                {"pubkey_x25519", sn.pubkey_x25519.hex()},
                {"pubkey_ed25519", sn.pubkey_ed25519.hex()},
                {"port", std::to_string(sn.port)}, // Deprecated port (as a string) for backwards compat; use "port_https" instead
                {"port_https", sn.port},
                {"port_omq", sn.omq_port},
                {"ip", sn.ip}});
    }

    return json{
        {"snodes", std::move(snodes_json)},
        {"swarm", util::int_to_string(swarm.swarm_id, 16)}
    };
}

std::string obfuscate_pubkey(const user_pubkey_t& pk) {
    const auto& pk_raw = pk.raw();
    if (pk_raw.empty())
        return "(none)";
    return oxenmq::to_hex(pk_raw.begin(), pk_raw.begin() + 2)
        + u8"…" + oxenmq::to_hex(std::prev(pk_raw.end()), pk_raw.end());
}

template <typename RPC>
void register_client_rpc_endpoint(RequestHandler::rpc_map& regs) {
    auto call = [](RequestHandler& h, const json& params, std::function<void(Response)> cb) {
        RPC req;
        req.load_from(params);
        if constexpr (std::is_base_of_v<rpc::recursive, RPC>)
            req.recurse = true; // Requests through HTTP or onion reqs are *always* client requests, so always recurse
        h.process_client_req(std::move(req), std::move(cb));
    };
    for (auto& name : RPC::names()) {
        [[maybe_unused]] auto [it, ins] = regs.emplace(name, call);
        assert(ins);
    }
}

template <typename... RPC>
RequestHandler::rpc_map register_client_rpc_endpoints(rpc::type_list<RPC...>) {
    RequestHandler::rpc_map regs;
    (register_client_rpc_endpoint<RPC>(regs), ...);
    return regs;
}

// For any integer (or timestamp) arguments convert to string using the provided buffer; returns a
// string_view into the relevant part of the buffer for converted integer/timestamp values.  If
// called with non-integer values then this simply returns an empty string_view.
template <typename T>
std::string_view convert_integer_arg(char*& buffer, const T& val) {
    if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
        return detail::to_hashable(val, buffer);
    else
        return {};
}

template <typename T, typename... More, size_t N>
size_t space_needed(const std::array<std::string_view, N>& stringified_ints, const T& val, const More&... more) {
    static_assert(N >= sizeof...(More) + 1);
    size_t s = 0;
    if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
        s = stringified_ints[N - sizeof...(More) - 1].size();
    else if constexpr (std::is_convertible_v<T, std::string_view>)
        s += std::string_view{val}.size();
    else {
        static_assert(std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, std::vector<std::string_view>>);
        for (auto& v : val)
            s += v.size();
    }
    if constexpr (sizeof...(More) > 0)
        s += space_needed(stringified_ints, more...);
    return s;
}

template <typename T, typename... More, size_t N>
void concatenate_parts(std::string& result, const std::array<std::string_view, N>& stringified_ints, const T& val, const More&... more) {
    static_assert(N >= sizeof...(More) + 1);
    if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
        result += stringified_ints[N - sizeof...(More) - 1];
    else if constexpr (std::is_convertible_v<T, std::string_view>)
        result += std::string_view{val};
    else {
        static_assert(std::is_same_v<T, std::vector<std::string>> || std::is_same_v<T, std::vector<std::string_view>>);
        for (auto& v : val)
            result += v;
    }
    if constexpr (sizeof...(More) > 0)
        concatenate_parts(result, stringified_ints, more...);
}

// This uses the above to make a std::string containing all the parts (stringifying when the parts
// contain integer or time_point values) concatenated together.  The implementation is a bit
// complicated using the various templates above because we do this trying to minimize the number of
// allocations we have to perform.
template <typename... T>
std::string concatenate_sig_message_parts(const T&... vals) {
    constexpr size_t num_ints = (0 + ... + (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>));
    // Buffer big enough to hold all our integer arguments:
    std::array<char, 20*num_ints> int_buffer;
    char* buffer_ptr = int_buffer.data();
    std::array<std::string_view, sizeof...(T)> stringified_ints{{convert_integer_arg(buffer_ptr, vals)...}};

    std::string data;
    // Don't reserve when we have a single int argument because SSO may avoid an allocation entirely
    if (!(num_ints == 1 && sizeof...(T) == 1))
        data.reserve(space_needed(stringified_ints, vals...));
    concatenate_parts(data, stringified_ints, vals...);
    return data;
}

template <typename... T>
bool verify_signature(
        const user_pubkey_t& pubkey,
        const std::optional<std::array<unsigned char, 32>>& pk_ed25519,
        const std::array<unsigned char, 64>& sig,
        const T&... val) {
    std::string data = concatenate_sig_message_parts(val...);
    const auto& raw = pubkey.raw();
    const unsigned char* pk;
    if ((pubkey.type() == 5 || (pubkey.type() == 0 && !is_mainnet)) && pk_ed25519) {
        pk = pk_ed25519->data();

        // Verify that the given ed pubkey actually converts to the x25519 pubkey
        std::array<unsigned char, crypto_scalarmult_curve25519_BYTES> xpk;
        if (crypto_sign_ed25519_pk_to_curve25519(xpk.data(), pk) != 0
                || std::memcmp(xpk.data(), raw.data(), crypto_scalarmult_curve25519_BYTES) != 0)
            return false;
    }
    else
        pk = reinterpret_cast<const unsigned char*>(raw.data());

    return 0 == crypto_sign_verify_detached(
            sig.data(),
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            pk);
}

template <typename... T>
std::array<unsigned char, 64> create_signature(const ed25519_seckey& sk, const T&... val) {
    std::array<unsigned char, 64> sig;
    std::string data = concatenate_sig_message_parts(val...);
    crypto_sign_detached(
            sig.data(),
            nullptr,
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            sk.data());
    return sig;
}

} // anon. namespace

const RequestHandler::rpc_map RequestHandler::client_rpc_endpoints =
    register_client_rpc_endpoints(rpc::client_rpc_types{});

std::string compute_hash_blake2b_b64(std::vector<std::string_view> parts) {
    constexpr size_t HASH_SIZE = 32;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASH_SIZE);
    for (const auto& s : parts)
        crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(s.data()), s.size());
    std::array<unsigned char, HASH_SIZE> hash;
    crypto_generichash_final(&state, hash.data(), HASH_SIZE);

    std::string b64hash = oxenmq::to_base64(hash.begin(), hash.end());
    // Trim padding:
    while (!b64hash.empty() && b64hash.back() == '=')
        b64hash.pop_back();
    return b64hash;
}

std::string compute_hash_sha512_hex(std::vector<std::string_view> parts) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    for (const auto& p : parts)
        SHA512_Update(&ctx, p.data(), p.size());

    std::array<unsigned char, SHA512_DIGEST_LENGTH> hash;
    SHA512_Final(hash.data(), &ctx);
    return oxenmq::to_hex(hash.begin(), hash.end());
}

std::string computeMessageHash(
        system_clock::time_point timestamp,
        system_clock::time_point expiry,
        const user_pubkey_t& pubkey,
        std::string_view data,
        bool old) {
    if (old) {
        return compute_hash(compute_hash_sha512_hex,
                timestamp,
                to_epoch_ms(expiry) - to_epoch_ms(timestamp), // ttl
                pubkey.prefixed_hex(),
                oxenmq::to_base64(data));
    }

    char netid = static_cast<char>(pubkey.type());
    return compute_hash(compute_hash_blake2b_b64,
            timestamp, expiry, std::string_view{&netid, 1}, pubkey.raw(), data);
}



bool validateTimestamp(system_clock::time_point timestamp, system_clock::time_point expiry) {
    auto now = system_clock::now();
    return timestamp <= now + 10s // Timestamp must not be in the future (with some tolerance)
        && expiry >= now - 10s; // Expiry must not be in the past (with some tolerance)
}

bool validateTTL(system_clock::duration ttl) {
    return ttl >= TTL_MINIMUM && ttl <= TTL_MAXIMUM;
}


RequestHandler::RequestHandler(
        ServiceNode& sn,
        const ChannelEncryption& ce,
        ed25519_seckey edsk)
    : service_node_{sn}, channel_cipher_(ce), ed25519_sk_{std::move(edsk)} {

    // Periodically clean up any proxy request futures
    service_node_.omq_server()->add_timer([this] {
        pending_proxy_requests_.remove_if(
                [](auto& f) { return f.wait_for(0ms) == std::future_status::ready; });
    }, 1s);
}

Response RequestHandler::handle_wrong_swarm(const user_pubkey_t& pubKey) {

    OXEN_LOG(trace, "Got client request to a wrong swarm");

    return {
        http::MISDIRECTED_REQUEST,
        swarm_to_json(service_node_.get_swarm(pubKey))};
}

struct swarm_response {
    std::mutex mutex;
    int pending;
    bool b64;
    nlohmann::json result;
    std::function<void(oxen::Response)> cb;
};

// Replies to a recursive swarm request via its callback; sends an http::OK unless all of the swarm
// entries returned things with "failed" in them, in which case we send back an
// INTERNAL_SERVER_ERROR along with the response.
void reply_or_fail(const std::shared_ptr<swarm_response>& res) {
    auto res_code = http::INTERNAL_SERVER_ERROR;
    for (const auto& [snode, reply] : res->result.items()) {
        if (!reply.count("failed")) {
            res_code = http::OK;
            break;
        }
    }
    res->cb(Response{res_code, std::move(res->result)});
}


static void distribute_command(
        ServiceNode& sn,
        std::shared_ptr<swarm_response>& res,
        std::string_view cmd,
        const rpc::recursive& req) {
    auto peers = sn.get_swarm_peers();
    res->pending += peers.size();

    for (auto& peer : peers) {
        sn.omq_server()->request(
                peer.pubkey_x25519.view(),
                "sn.storage_cc",
                [res, peer, cmd](bool success, auto parts) {
                    json peer_result;
                    if (!success)
                        OXEN_LOG(warn, "Response timeout from {} for forwarded command {}",
                                peer.pubkey_legacy, cmd);
                    bool good_result = success && parts.size() == 1;
                    if (good_result) {
                        try {
                            peer_result = bt_to_json(oxenmq::bt_dict_consumer{parts[0]});
                        } catch (const std::exception& e) {
                            OXEN_LOG(warn, "Received unparseable response to {} from {}: {}",
                                    cmd, peer.pubkey_legacy, e.what());
                            good_result = false;
                        }
                    }

                    std::lock_guard lock{res->mutex};

                    // If we're the last response then we reply:
                    bool send_reply = --res->pending == 0;

                    if (!good_result) {
                        peer_result = json{{"failed", true}};
                        if (!success) peer_result["timeout"] = true;
                        else if (parts.size() == 2) {
                            peer_result["code"] = parts[0];
                            peer_result["reason"] = parts[1];
                        }
                        else peer_result["bad_peer_response"] = true;
                    }
                    else if (res->b64) {
                        if (auto it = peer_result.find("signature"); it != peer_result.end() && it->is_string())
                            *it = oxenmq::to_base64(it->get_ref<const std::string&>());
                    }

                    res->result["swarm"][peer.pubkey_ed25519.hex()] = std::move(peer_result);

                    if (send_reply)
                        reply_or_fail(res);
                },
                cmd,
                bt_serialize(req.to_bt()),
                oxenmq::send_option::request_timeout{5s}
        );
    }
}

template <typename RPC, typename = std::enable_if_t<std::is_base_of_v<rpc::recursive, RPC>>>
std::pair<std::shared_ptr<swarm_response>, std::unique_lock<std::mutex>>
static setup_recursive_request(ServiceNode& sn, RPC& req, std::function<void(Response)> cb) {
    auto res = std::make_shared<swarm_response>();
    res->cb = std::move(cb);
    res->pending = 1;
    res->b64 = req.b64;

    std::unique_lock<std::mutex> lock{res->mutex, std::defer_lock};
    if (req.recurse) {
        // Send it off to our peers right away, before we process it ourselves
        distribute_command(sn, res, RPC::names()[0], req);
        lock.lock();
    }
    return {std::move(res), std::move(lock)};
}

void RequestHandler::process_client_req(
        rpc::store&& req, std::function<void(Response)> cb) {

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "Storing message: {}", oxenmq::to_base64(req.data));

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    using namespace std::chrono;
    auto ttl = duration_cast<milliseconds>(req.expiry - req.timestamp);
    if (!validateTTL(ttl)) {
        OXEN_LOG(warn, "Forbidden. Invalid TTL: {}ms", ttl.count());
        return cb(Response{http::FORBIDDEN, "Provided expiry/TTL is not valid."sv});
    }
    if (!validateTimestamp(req.timestamp, req.expiry)) {
        OXEN_LOG(debug, "Forbidden. Invalid Timestamp: {}", to_epoch_ms(req.timestamp));
        return cb(Response{http::NOT_ACCEPTABLE, "Timestamp error: check your clock"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    bool use_old_hash = !service_node_.hf_at_least(HARDFORK_HASH_BLAKE2B);
    std::string message_hash = computeMessageHash(
            req.timestamp, req.expiry, req.pubkey, req.data, use_old_hash);

    bool new_msg;
    bool success = false;
    try {
        success = service_node_.process_store(message{
            req.pubkey, message_hash, req.timestamp, req.expiry, std::move(req.data)}, &new_msg);
    } catch (const std::exception& e) {
        OXEN_LOG(err, "Internal Server Error. Could not store message for {}: {}",
                obfuscate_pubkey(req.pubkey), e.what());
        mine["reason"] = e.what();
    }
    if (success) {
        mine["hash"] = message_hash;
        auto sig = create_signature(ed25519_sk_, message_hash);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
        if (!new_msg) mine["already"] = true;
        if (req.recurse) {
            // Backwards compat: put the hash at top level, too.  TODO: remove eventually
            res->result["hash"] = message_hash;
            // No longer used, but here to avoid breaking older clients.  TODO: remove eventually
            res->result["difficulty"] = 1;
        }
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    OXEN_LOG(trace, "Successfully stored message {} for {}", message_hash, obfuscate_pubkey(req.pubkey));

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
        rpc::oxend_request&& req, std::function<void(oxen::Response)> cb) {

    std::optional<std::string> oxend_params;
    if (req.params)
        oxend_params = req.params->dump();

    service_node_.omq_server().oxend_request(
        "rpc." + req.endpoint,
        [cb = std::move(cb)](bool success, auto&& data) {
            std::string err;
            // Currently we only support json endpoints; if we want to support non-json endpoints
            // (which end in ".bin") at some point in the future then we'll need to return those
            // endpoint results differently here.
            if (success && data.size() >= 2 && data[0] == "200") {
                json result = json::parse(data[1], nullptr, false);
                if (result.is_discarded()) {
                    OXEN_LOG(warn, "Invalid oxend response to client request: result is not valid json");
                    return cb({http::BAD_GATEWAY, "oxend returned unparseable data"s});
                }
                return cb({http::OK, json{{"result", std::move(result)}}});
            }
            return cb({http::BAD_REQUEST,
                data.size() >= 2 && !data[1].empty()
                    ? std::move(data[1]) : "Unknown oxend error"s});
        },
        oxend_params);
}

void RequestHandler::process_client_req(
        rpc::get_swarm&& req, std::function<void(oxen::Response)> cb) {

    const auto swarm = service_node_.get_swarm(req.pubkey);

    OXEN_LOG(debug, "get swarm for {}, swarm size: {}",
            obfuscate_pubkey(req.pubkey), swarm.snodes.size());

    auto body = swarm_to_json(swarm);

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "swarm details for pk {}: {}", obfuscate_pubkey(req.pubkey), body.dump());

    cb(Response{http::OK, std::move(body)});
}

void RequestHandler::process_client_req(
        rpc::retrieve&& req, std::function<void(oxen::Response)> cb) {

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    std::vector<message> msgs;
    try {
        msgs = service_node_.retrieve(req.pubkey, req.last_hash.value_or(""));
    } catch (const std::exception& e) {
        auto msg = fmt::format("Internal Server Error. Could not retrieve messages for {}",
                obfuscate_pubkey(req.pubkey));
        OXEN_LOG(critical, msg);
        return cb(Response{http::INTERNAL_SERVER_ERROR, std::move(msg)});
    }

    OXEN_LOG(trace, "Retrieved {} messages for {}", msgs.size(), obfuscate_pubkey(req.pubkey));

    json messages = json::array();
    for (const auto& msg : msgs) {
        messages.push_back(json{
            {"hash", msg.hash},
            {"timestamp", to_epoch_ms(msg.timestamp)},
            {"expiration", to_epoch_ms(msg.expiry)},
            {"data", req.b64 ? oxenmq::to_base64(msg.data) : std::move(msg.data)},
        });
    }

    return cb(Response{http::OK, json{{"messages", std::move(messages)}}});
}

void RequestHandler::process_client_req(
        rpc::info&&, std::function<void(oxen::Response)> cb) {

    return cb(Response{http::OK,
        json{
            {"version", STORAGE_SERVER_VERSION},
            {"timestamp", to_epoch_ms(system_clock::now())}
        }});
}

void RequestHandler::process_client_req(
        rpc::delete_all&& req, std::function<void(oxen::Response)> cb) {
    OXEN_LOG(debug, "processing delete_all {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.timestamp < now - 1min || req.timestamp > now + 1min) {
        OXEN_LOG(debug, "delete_all: invalid timestamp ({}s from now)", duration_cast<seconds>(req.timestamp - now).count());
        return cb(Response{http::UNAUTHORIZED, "delete_all timestamp too far from current time"sv});
    }

    if (!verify_signature(req.pubkey, req.pubkey_ed25519, req.signature, "delete_all", req.timestamp)) {
        OXEN_LOG(debug, "delete_all: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_all signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    if (auto deleted = service_node_.delete_all_messages(req.pubkey)) {
        std::sort(deleted->begin(), deleted->end());
        auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.timestamp, *deleted);
        mine["deleted"] = std::move(*deleted);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
        rpc::delete_msgs&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing delete_msgs {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    if (!verify_signature(req.pubkey, req.pubkey_ed25519, req.signature, "delete", req.messages)) {
        OXEN_LOG(debug, "delete_msgs: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_msgs signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    if (auto deleted = service_node_.delete_messages(req.pubkey, req.messages)) {
        std::sort(deleted->begin(), deleted->end());
        auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.messages, *deleted);
        mine["deleted"] = std::move(*deleted);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
        rpc::delete_before&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing delete_before {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.before > now + 1min) {
        OXEN_LOG(debug, "delete_before: invalid timestamp ({}s from now)", duration_cast<seconds>(req.before - now).count());
        return cb(Response{http::UNAUTHORIZED, "delete_before timestamp too far in the future"sv});
    }

    if (!verify_signature(req.pubkey, req.pubkey_ed25519, req.signature, "delete_before", req.before)) {
        OXEN_LOG(debug, "delete_before: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_before signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    if (auto deleted = service_node_.delete_messages_before(req.pubkey, req.before)) {
        std::sort(deleted->begin(), deleted->end());
        auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.before, *deleted);
        mine["deleted"] = std::move(*deleted);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
        rpc::expire_all&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing expire_all {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.expiry < now - 1min) {
        OXEN_LOG(debug, "expire_all: invalid timestamp ({}s ago)", duration_cast<seconds>(now - req.expiry).count());
        return cb(Response{http::UNAUTHORIZED, "expire_all timestamp should be >= current time"sv});
    }

    if (!verify_signature(req.pubkey, req.pubkey_ed25519, req.signature, "expire_all", req.expiry)) {
        OXEN_LOG(debug, "expire_all: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "expire_all signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    if (auto updated = service_node_.update_all_expiries(req.pubkey, req.expiry)) {
        std::sort(updated->begin(), updated->end());
        auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.expiry, *updated);
        mine["updated"] = std::move(*updated);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}
void RequestHandler::process_client_req(
        rpc::expire_msgs&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing expire_msgs {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.expiry < now - 1min) {
        OXEN_LOG(debug, "expire_all: invalid timestamp ({}s ago)", duration_cast<seconds>(now - req.expiry).count());
        return cb(Response{http::UNAUTHORIZED, "expire_all timestamp should be >= current time"sv});
    }

    if (!verify_signature(req.pubkey, req.pubkey_ed25519, req.signature, "expire", req.messages)) {
        OXEN_LOG(debug, "expire_msgs: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "expire_msgs signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
        ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
        : res->result;

    if (auto updated = service_node_.update_messages_expiry(req.pubkey, req.messages, req.expiry)) {
        std::sort(updated->begin(), updated->end());
        auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.expiry, req.messages, *updated);
        mine["updated"] = std::move(*updated);
        mine["signature"] = req.b64 ? oxenmq::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
    std::string_view req_json, std::function<void(Response)> cb) {

    OXEN_LOG(trace, "process_client_req str <{}>", req_json);

    json body = json::parse(req_json, nullptr, false);
    if (body.is_discarded()) {
        OXEN_LOG(debug, "Bad client request: invalid json");
        return cb(Response{http::BAD_REQUEST, "invalid json"sv});
    }

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "process_client_req json <{}>", body.dump(2));

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        OXEN_LOG(debug, "Bad client request: no method field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `method` field"sv});
    }

    std::string_view method_name = method_it->get_ref<const std::string&>();

    OXEN_LOG(trace, "  - method name: {}", method_name);

    auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        OXEN_LOG(debug, "Bad client request: no params field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `params` field"sv});
    }

    process_client_req(method_name, std::move(*params_it), std::move(cb));
}

void RequestHandler::process_client_req(
        std::string_view method_name,
        json params,
        std::function<void(Response)> cb) {

    if (auto it = client_rpc_endpoints.find(method_name);
            it != client_rpc_endpoints.end()) {
        OXEN_LOG(debug, "Process client request: {}", method_name);
        try {
            return it->second(*this, std::move(params), cb);
        } catch (const rpc::parse_error& e) {
            // These exceptions carry a failure message to send back to the client
            OXEN_LOG(debug, "Invalid request: {}", e.what());
            return cb(Response{http::BAD_REQUEST, "invalid request: "s + e.what()});
        } catch (const std::exception& e) {
            // Other exceptions might contain something sensitive or irrelevant so warn about it and
            // send back a generic message.
            OXEN_LOG(warn, "Client request raised an exception: {}", e.what());
            return cb(Response{http::INTERNAL_SERVER_ERROR, "request failed"sv});
        }
    }

    OXEN_LOG(debug, "Bad client request: unknown method '{}'", method_name);
    return cb({http::BAD_REQUEST, "no method " + std::string{method_name}});
}

Response RequestHandler::process_retrieve_all() {

    std::vector<message> msgs;
    try {
        msgs = service_node_.get_all_messages();
    } catch (const std::exception& e) {
        return {http::INTERNAL_SERVER_ERROR, "could not retrieve all messages"s};
    }

    json messages = json::array();
    for (auto& m : msgs)
        messages.push_back(json{{"data", std::move(m.data)}, {"pk", m.pubkey.prefixed_hex()}});

    return {http::OK, json{{"messages", std::move(messages)}}};
}


void RequestHandler::process_storage_test_req(
        uint64_t height,
        legacy_pubkey tester,
        std::string msg_hash_hex,
        std::function<void(MessageTestStatus, std::string, steady_clock::duration)> callback) {

    /// TODO: we never actually test that `height` is within any reasonable
    /// time window (or that it is not repeated multiple times), we should do
    /// that! This is done implicitly to some degree using
    /// `block_hashes_cache_`, which holds a limited number of recent blocks
    /// only and fails if an earlier block is requested

    auto started = steady_clock::now();
    auto [status, answer] = service_node_.process_storage_test_req(
            height, tester, msg_hash_hex);

    if (status == MessageTestStatus::RETRY) {
        // Our first attempt returned a RETRY, so set up a timer to keep retrying

        auto timer = std::make_shared<oxenmq::TimerID>();
        auto& timer_ref = *timer;
        service_node_.omq_server()->add_timer(timer_ref, [
                this,
                timer=std::move(timer),
                height,
                tester,
                hash=std::move(msg_hash_hex),
                started,
                callback=std::move(callback)] {
            auto elapsed = steady_clock::now() - started;

            OXEN_LOG(trace, "Performing storage test retry, {} since started",
                    util::friendly_duration(elapsed));

            auto [status, answer] = service_node_.process_storage_test_req(
                    height, tester, hash);
            if (status == MessageTestStatus::RETRY && elapsed < TEST_RETRY_PERIOD && !service_node_.shutting_down())
                return; // Still retrying so wait for the next call
            service_node_.omq_server()->cancel_timer(*timer);
            callback(status, std::move(answer), elapsed);
        }, TEST_RETRY_INTERVAL);
    } else {
        callback(status, std::move(answer), steady_clock::now() - started);
    }
}

Response RequestHandler::wrap_proxy_response(Response res,
                                             const x25519_pubkey& client_key,
                                             EncryptType enc_type,
                                             bool embed_json,
                                             bool base64) const {

    int status = res.status.first;
    std::string body;
    if (std::holds_alternative<std::string>(res.body))
        body = json{{"status", status}, {"body", std::move(std::get<std::string>(res.body))}}.dump();
    else if (std::holds_alternative<std::string_view>(res.body))
        body = json{{"status", status}, {"body", std::get<std::string_view>(res.body)}}.dump();
    else if (embed_json)
        body = json{{"status", status}, {"body", std::move(std::get<json>(res.body))}}.dump();
    else // Yuck: double-encoded json
        body = json{{"status", status}, {"body", std::get<json>(res.body).dump()}}.dump();

    std::string ciphertext = channel_cipher_.encrypt(enc_type, body, client_key);
    if (base64)
        ciphertext = oxenmq::to_base64(std::move(ciphertext));

    return Response{http::OK, std::move(ciphertext)};
}

void RequestHandler::process_onion_req(std::string_view ciphertext,
                                       OnionRequestMetadata data) {
    if (!service_node_.snode_ready())
        return data.cb({
            http::SERVICE_UNAVAILABLE,
            fmt::format("Snode not ready: {}", service_node_.own_address().pubkey_ed25519)});

    OXEN_LOG(debug, "process_onion_req");

    service_node_.record_onion_request();

    var::visit([&](auto&& x) { process_onion_req(std::move(x), std::move(data)); },
            process_ciphertext_v2(channel_cipher_, ciphertext, data.ephem_key, data.enc_type));
}

void RequestHandler::process_onion_req(FinalDestinationInfo&& info,
        OnionRequestMetadata&& data) {
    OXEN_LOG(debug, "We are the target of the onion request!");

    if (!service_node_.snode_ready())
        return data.cb(wrap_proxy_response({http::SERVICE_UNAVAILABLE, "Snode not ready"s},
                    data.ephem_key, data.enc_type, info.json, info.base64));

    process_client_req(
            info.body,
            [this, data = std::move(data), json = info.json, b64 = info.base64]
            (oxen::Response res) {
                data.cb(wrap_proxy_response(std::move(res), data.ephem_key, data.enc_type, json, b64));
            });
}

void RequestHandler::process_onion_req(RelayToNodeInfo&& info,
        OnionRequestMetadata&& data) {
    auto& [payload, ekey, etype, dest] = info;

    auto dest_node = service_node_.find_node(dest);
    if (!dest_node) {
        auto msg = fmt::format("Next node not found: {}", dest);
        OXEN_LOG(warn, "{}", msg);
        return data.cb({http::BAD_GATEWAY, std::move(msg)});
    }

    auto on_response = [cb=std::move(data.cb)](bool success, std::vector<std::string> data) {
        // Processing the result we got from upstream

        if (!success) {
            OXEN_LOG(debug, "[Onion request] Request time out");
            return cb({http::GATEWAY_TIMEOUT, "Request time out"s});
        }

        // We expect a two-part message, but for forwards compatibility allow extra parts
        if (data.size() < 2) {
            OXEN_LOG(debug, "[Onion request] Invalid response; expected at least 2 parts");
            return cb({http::INTERNAL_SERVER_ERROR, "Invalid response from snode"s});
        }

        Response res{http::INTERNAL_SERVER_ERROR, std::move(data[1])};
        if (int code; util::parse_int(data[0], code))
            res.status = http::from_code(code);

        /// We use http status codes (for now)
        if (res.status != http::OK)
            OXEN_LOG(debug, "Onion request relay failed with: {}",
                    std::holds_alternative<nlohmann::json>(res.body) ? "<json>" : view_body(res));

        cb(std::move(res));
    };

    OXEN_LOG(debug, "send_onion_to_sn, sn: {}", dest_node->pubkey_legacy);

    data.ephem_key = ekey;
    data.enc_type = etype;
    service_node_.send_onion_to_sn(
            *dest_node, std::move(payload), std::move(data), std::move(on_response));
}


void RequestHandler::process_onion_req(
        RelayToServerInfo&& info, OnionRequestMetadata&& data) {
    OXEN_LOG(debug, "We are to forward the request to url: {}{}",
            info.host, info.target);

    // Forward the request to url but only if it ends in `/lsrpc`
    if (!(info.protocol == "http" || info.protocol == "https") ||
            !is_onion_url_target_allowed(info.target))
        return data.cb(wrap_proxy_response({http::BAD_REQUEST, "Invalid url"s},
            data.ephem_key, data.enc_type));

    std::string urlstr;
    urlstr.reserve(info.protocol.size() + 3 + info.host.size() + 6 /*:port*/ + 1 + info.target.size());
    urlstr += info.protocol;
    urlstr += "://";
    urlstr += info.host;
    if (info.port != (info.protocol == "https" ? 443 : 80)) {
        urlstr += ':';
        urlstr += std::to_string(info.port);
    }
    if (!util::starts_with(info.target, "/"))
        urlstr += '/';
    urlstr += info.target;

    service_node_.record_proxy_request();

    pending_proxy_requests_.emplace_front(
        cpr::PostCallback(
            [&omq=*service_node_.omq_server(), cb=std::move(data.cb)](cpr::Response r) {
                Response res;
                if (r.error.code != cpr::ErrorCode::OK) {
                    OXEN_LOG(debug, "Onion proxied request to {} failed: {}", r.url.str(), r.error.message);
                    res.body = r.error.message;
                    if (r.error.code == cpr::ErrorCode::OPERATION_TIMEDOUT)
                        res.status = http::GATEWAY_TIMEOUT;
                    else
                        res.status = http::BAD_GATEWAY;
                } else {
                    res.status.first = r.status_code;
                    res.status.second = r.status_line;
                    for (auto& [k, v] : r.header)
                        res.headers.emplace_back(std::move(k), std::move(v));
                    res.body = std::move(r.text);
                }

                cb(std::move(res));
            },
            cpr::Url{std::move(urlstr)},
            cpr::Timeout{ONION_URL_TIMEOUT},
            cpr::Ssl(cpr::ssl::TLSv1_2{}),
            cpr::MaxRedirects{0},
            cpr::Body{std::move(info.payload)}
        )
    );
}

void RequestHandler::process_onion_req(ProcessCiphertextError&& error,
        OnionRequestMetadata&& data) {

    switch (error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT:
            return data.cb({http::BAD_REQUEST, "Invalid ciphertext"s});
        case ProcessCiphertextError::INVALID_JSON:
            return data.cb(wrap_proxy_response({http::BAD_REQUEST, "Invalid json"s},
                    data.ephem_key, data.enc_type));
    }
}

} // namespace oxen
