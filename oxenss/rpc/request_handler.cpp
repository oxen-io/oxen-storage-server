#include "request_handler.h"
#include <oxenss/crypto/channel_encryption.hpp>
#include "client_rpc_endpoints.h"
#include <oxenss/server/utils.h>
#include <oxenss/server/omq.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/crypto/signature.h>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/time.hpp>
#include <oxenss/version.h>
#include <oxenss/common/mainnet.h>

#include <chrono>
#include <future>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <type_traits>
#include <variant>

using nlohmann::json;
using namespace std::chrono;

namespace oxen::rpc {

// Timeout for onion-request-to-url requests.  Onion requests have a 30s timeout so we choose a
// timeout a bit shorter than that so that we still have a good chance of the error response
// getting back to the client before the entry node's request times out.
inline constexpr auto ONION_URL_TIMEOUT = 25s;

std::string to_string(const Response& res) {
    std::stringstream ss;

    const bool is_json = std::holds_alternative<json>(res.body);
    ss << "Status: " << res.status.first << " " << res.status.second
       << ", Content-Type: " << (is_json ? "application/json" : "text/plain") << ", Body: <"
       << (is_json ? std::get<json>(res.body).dump() : view_body(res)) << ">";

    return ss.str();
}

namespace {
    json swarm_to_json(const snode::SwarmInfo& swarm) {
        json snodes_json = json::array();
        for (const auto& sn : swarm.snodes) {
            snodes_json.push_back(
                    json{{"address",  // Deprecated, use pubkey_legacy instead
                          oxenc::to_base32z(sn.pubkey_legacy.view()) + ".snode"},
                         {"pubkey_legacy", sn.pubkey_legacy.hex()},
                         {"pubkey_x25519", sn.pubkey_x25519.hex()},
                         {"pubkey_ed25519", sn.pubkey_ed25519.hex()},
                         {"port",  // Deprecated string port for backwards compat; prefer https_port
                          std::to_string(sn.port)},
                         {"port_https", sn.port},
                         {"port_omq", sn.omq_port},
                         {"ip", sn.ip}});
        }

        return json{
                {"snodes", std::move(snodes_json)},
                {"swarm", util::int_to_string(swarm.swarm_id, 16)},
        };
    }

    void add_misc_response_fields(
            json& j,
            snode::ServiceNode& sn,
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
        j["t"] = to_epoch_ms(now);
        j["hf"] = sn.hf();
    }

    std::string obfuscate_pubkey(const user_pubkey_t& pk) {
        const auto& pk_raw = pk.raw();
        if (pk_raw.empty())
            return "(none)";
        return oxenc::to_hex(pk_raw.begin(), pk_raw.begin() + 2) + u8"…" +
               oxenc::to_hex(std::prev(pk_raw.end()), pk_raw.end());
    }

    template <typename RPC, typename Params>
    RPC load_request(Params&& params) {
        RPC req;
        req.load_from(std::forward<Params>(params));
        if constexpr (std::is_base_of_v<rpc::recursive, RPC>)
            // This func is only called for loading subrequests and http_json requests, both of
            // which are only initiated by a top-level client so we are always going to recurse:
            req.recurse = true;
        return req;
    }

    template <typename RPC>
    void register_client_rpc_endpoint(RequestHandler::rpc_map& regs) {
        RequestHandler::rpc_handler calls;
        if constexpr (!std::is_base_of_v<batch, RPC>) {
            calls.load_subreq_json = [](json params) -> client_subrequest {
                return load_request<RPC>(std::move(params));
            };
            calls.load_subreq_bt = [](oxenc::bt_dict_consumer params) -> client_subrequest {
                return load_request<RPC>(std::move(params));
            };
        }
        calls.http_json = [](RequestHandler& h, json params, std::function<void(Response)> cb) {
            auto req = load_request<RPC>(std::move(params));
            h.process_client_req(std::move(req), std::move(cb));
        };
        calls.omq = [](rpc::RequestHandler& h,
                       std::string_view params,
                       [[maybe_unused]] bool forwarded,
                       std::function<void(rpc::Response)> cb) {
            RPC req;
            if (params.empty())
                params = "{}"sv;
            if (params.front() == 'd') {
                req.load_from(oxenc::bt_dict_consumer{params});
                req.b64 = false;
            } else {
                auto body = nlohmann::json::parse(params, nullptr, false);
                if (body.is_discarded()) {
                    OXEN_LOG(debug, "Bad OMQ client request: not valid json or bt_dict");
                    return cb(rpc::Response{
                            http::BAD_REQUEST, "invalid body: expected json or bt_dict"sv});
                }
                req.load_from(std::move(body));
            }
            if constexpr (std::is_base_of_v<rpc::recursive, RPC>) {
                req.recurse = !forwarded;
            } else if (forwarded) {
                return cb(rpc::Response{
                        http::BAD_REQUEST,
                        "invalid request: received invalid forwarded non-forwardable request"sv});
            }

            h.process_client_req(std::move(req), std::move(cb));
        };

        for (auto& name : RPC::names()) {
            [[maybe_unused]] auto [it, ins] = regs.emplace(name, calls);
            assert(ins);
        }
    }

    template <typename... RPC>
    RequestHandler::rpc_map register_client_rpc_endpoints(type_list<RPC...>) {
        RequestHandler::rpc_map regs;
        (register_client_rpc_endpoint<RPC>(regs), ...);
        return regs;
    }

    // For any integer (or timestamp) arguments convert to string using the provided buffer;
    // returns a string_view into the relevant part of the buffer for converted
    // integer/timestamp values.  If called with non-integer values then this simply returns an
    // empty string_view.
    template <typename T>
    std::string_view convert_integer_arg(char*& buffer, const T& val) {
        if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
            return detail::to_hashable(val, buffer);
        else
            return {};
    }

    template <typename T, typename... More, size_t N>
    size_t space_needed(
            const std::array<std::string_view, N>& stringified_ints,
            const T& val,
            const More&... more) {
        static_assert(N >= sizeof...(More) + 1);
        size_t s = 0;
        if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
            s = stringified_ints[N - sizeof...(More) - 1].size();
        else if constexpr (std::is_convertible_v<T, std::string_view>)
            s += std::string_view{val}.size();
        else {
            static_assert(
                    std::is_same_v<T, std::vector<std::string>> ||
                    std::is_same_v<T, std::vector<std::string_view>>);
            for (auto& v : val)
                s += v.size();
        }
        if constexpr (sizeof...(More) > 0)
            s += space_needed(stringified_ints, more...);
        return s;
    }

    template <typename T, typename... More, size_t N>
    void concatenate_parts(
            std::string& result,
            const std::array<std::string_view, N>& stringified_ints,
            const T& val,
            const More&... more) {
        static_assert(N >= sizeof...(More) + 1);
        if constexpr (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>)
            result += stringified_ints[N - sizeof...(More) - 1];
        else if constexpr (std::is_convertible_v<T, std::string_view>)
            result += std::string_view{val};
        else {
            static_assert(
                    std::is_same_v<T, std::vector<std::string>> ||
                    std::is_same_v<T, std::vector<std::string_view>>);
            for (auto& v : val)
                result += v;
        }
        if constexpr (sizeof...(More) > 0)
            concatenate_parts(result, stringified_ints, more...);
    }

    // This uses the above to make a std::string containing all the parts (stringifying when the
    // parts contain integer or time_point values) concatenated together.  The implementation is
    // a bit complicated using the various templates above because we do this trying to minimize
    // the number of allocations we have to perform.
    template <typename... T>
    std::string concatenate_sig_message_parts(const T&... vals) {
        constexpr size_t num_ints =
                (0 + ... + (std::is_integral_v<T> || std::is_same_v<T, system_clock::time_point>));
        // Buffer big enough to hold all our integer arguments:
        std::array<char, 20 * num_ints> int_buffer;
        char* buffer_ptr = int_buffer.data();
        std::array<std::string_view, sizeof...(T)> stringified_ints{
                {convert_integer_arg(buffer_ptr, vals)...}};

        std::string data;
        // Don't reserve when we have a single int argument because SSO may avoid an allocation
        // entirely
        if (!(num_ints == 1 && sizeof...(T) == 1))
            data.reserve(space_needed(stringified_ints, vals...));
        concatenate_parts(data, stringified_ints, vals...);
        return data;
    }

    template <typename... T>
    bool verify_signature(
            const user_pubkey_t& pubkey,
            const std::optional<std::array<unsigned char, 32>>& pk_ed25519,
            const std::optional<std::array<unsigned char, 32>>& subkey,
            const std::array<unsigned char, 64>& sig,
            const T&... val) {
        std::string data = concatenate_sig_message_parts(val...);
        const auto& raw = pubkey.raw();
        const unsigned char* pk;
        if ((pubkey.type() == 5 || (pubkey.type() == 0 && !is_mainnet)) && pk_ed25519) {
            pk = pk_ed25519->data();

            // Verify that the given ed pubkey actually converts to the x25519 pubkey
            std::array<unsigned char, crypto_scalarmult_curve25519_BYTES> xpk;
            if (crypto_sign_ed25519_pk_to_curve25519(xpk.data(), pk) != 0 ||
                std::memcmp(xpk.data(), raw.data(), crypto_scalarmult_curve25519_BYTES) != 0) {
                OXEN_LOG(debug, "Signature verification failed: ed -> x conversion did not match");
                return false;
            }
        } else
            pk = reinterpret_cast<const unsigned char*>(raw.data());

        std::array<unsigned char, 32> subkey_pub;
        if (subkey) {
            // Need to compute: (c + H(c || A)) A and use that instead of A for verification:

            // H(c || A):
            crypto_generichash_state h_state;
            crypto_generichash_init(
                    &h_state,
                    reinterpret_cast<const unsigned char*>(SUBKEY_HASH_KEY.data()),
                    SUBKEY_HASH_KEY.size(),
                    32);
            crypto_generichash_update(&h_state, subkey->data(), 32);  // c
            crypto_generichash_update(&h_state, pk, 32);              // A
            crypto_generichash_final(&h_state, subkey_pub.data(), 32);

            // c + H(c || A):
            crypto_core_ed25519_scalar_add(subkey_pub.data(), subkey->data(), subkey_pub.data());

            // (c + H(c || A)) A:
            if (0 != crypto_scalarmult_ed25519_noclamp(subkey_pub.data(), subkey_pub.data(), pk)) {
                OXEN_LOG(warn, "Signature verification failed: invalid subkey multiplication");
                return false;
            }
            pk = subkey_pub.data();
        }

        bool verified = 0 == crypto_sign_verify_detached(
                                     sig.data(),
                                     reinterpret_cast<const unsigned char*>(data.data()),
                                     data.size(),
                                     pk);
        if (!verified)
            OXEN_LOG(debug, "Signature verification failed");
        return verified;
    }

    template <typename... T>
    std::array<unsigned char, 64> create_signature(
            const crypto::ed25519_seckey& sk, const T&... val) {
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

}  // namespace

const RequestHandler::rpc_map RequestHandler::client_rpc_endpoints =
        register_client_rpc_endpoints(rpc::client_rpc_types{});

std::string compute_hash_blake2b_b64(std::vector<std::string_view> parts) {
    constexpr size_t HASH_SIZE = 32;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASH_SIZE);
    for (const auto& s : parts)
        crypto_generichash_update(
                &state, reinterpret_cast<const unsigned char*>(s.data()), s.size());
    std::array<unsigned char, HASH_SIZE> hash;
    crypto_generichash_final(&state, hash.data(), HASH_SIZE);

    std::string b64hash = oxenc::to_base64(hash.begin(), hash.end());
    // Trim padding:
    while (!b64hash.empty() && b64hash.back() == '=')
        b64hash.pop_back();
    return b64hash;
}

std::string computeMessageHash(
        system_clock::time_point timestamp,
        system_clock::time_point expiry,
        const user_pubkey_t& pubkey,
        namespace_id ns,
        std::string_view data) {
    char netid = static_cast<char>(pubkey.type());
    std::array<char, 20> ns_buf;
    char* ns_buf_ptr = ns_buf.data();
    std::string_view ns_for_hash =
            ns != namespace_id::Default ? detail::to_hashable(to_int(ns), ns_buf_ptr) : ""sv;
    return compute_hash(
            compute_hash_blake2b_b64,
            timestamp,
            expiry,
            std::string_view{&netid, 1},
            pubkey.raw(),
            ns_for_hash,
            data);
}

RequestHandler::RequestHandler(
        snode::ServiceNode& sn, const crypto::ChannelEncryption& ce, crypto::ed25519_seckey edsk) :
        service_node_{sn}, channel_cipher_(ce), ed25519_sk_{std::move(edsk)} {
    // Periodically clean up any proxy request futures
    service_node_.omq_server()->add_timer(
            [this] {
                pending_proxy_requests_.remove_if(
                        [](auto& f) { return f.wait_for(0ms) == std::future_status::ready; });
            },
            1s);
}

Response RequestHandler::handle_wrong_swarm(const user_pubkey_t& pubKey) {
    OXEN_LOG(trace, "Got client request to a wrong swarm");

    json swarm = swarm_to_json(service_node_.get_swarm(pubKey));
    add_misc_response_fields(swarm, service_node_);
    return {http::MISDIRECTED_REQUEST, std::move(swarm)};
}

struct swarm_response {
    std::mutex mutex;
    int pending;
    bool b64;
    nlohmann::json result;
    std::function<void(rpc::Response)> cb;
};

// Replies to a recursive swarm request via its callback; sends an http::OK unless all of the
// swarm entries returned things with "failed" in them, in which case we send back an
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
        snode::ServiceNode& sn,
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
                        OXEN_LOG(
                                warn,
                                "Response timeout from {} for forwarded command {}",
                                peer.pubkey_legacy,
                                cmd);
                    bool good_result = success && parts.size() == 1;
                    if (good_result) {
                        try {
                            peer_result = server::bt_to_json(oxenc::bt_dict_consumer{parts[0]});
                        } catch (const std::exception& e) {
                            OXEN_LOG(
                                    warn,
                                    "Received unparseable response to {} from {}: {}",
                                    cmd,
                                    peer.pubkey_legacy,
                                    e.what());
                            good_result = false;
                        }
                    }

                    std::lock_guard lock{res->mutex};

                    // If we're the last response then we reply:
                    bool send_reply = --res->pending == 0;

                    if (!good_result) {
                        peer_result = json{{"failed", true}};
                        if (!success)
                            peer_result["timeout"] = true;
                        else if (parts.size() == 2) {
                            peer_result["code"] = parts[0];
                            peer_result["reason"] = parts[1];
                        } else
                            peer_result["bad_peer_response"] = true;
                    } else if (res->b64) {
                        if (auto it = peer_result.find("signature");
                            it != peer_result.end() && it->is_string())
                            *it = oxenc::to_base64(it->get_ref<const std::string&>());
                    }

                    res->result["swarm"][peer.pubkey_ed25519.hex()] = std::move(peer_result);

                    if (send_reply)
                        reply_or_fail(res);
                },
                cmd,
                bt_serialize(req.to_bt()),
                oxenmq::send_option::request_timeout{5s});
    }
}

template <typename RPC, typename = std::enable_if_t<std::is_base_of_v<rpc::recursive, RPC>>>
std::pair<std::shared_ptr<swarm_response>, std::unique_lock<std::mutex>> static setup_recursive_request(
        snode::ServiceNode& sn, RPC& req, std::function<void(Response)> cb) {
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

void RequestHandler::process_client_req(rpc::store&& req, std::function<void(Response)> cb) {
    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "Storing message: {}", oxenc::to_base64(req.data));

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    using namespace std::chrono;
    auto ttl = duration_cast<milliseconds>(req.expiry - req.timestamp);
    if (ttl < TTL_MINIMUM || ttl > TTL_MAXIMUM) {
        OXEN_LOG(warn, "Forbidden. Invalid TTL: {}ms", ttl.count());
        return cb(Response{http::FORBIDDEN, "Provided expiry/TTL is not valid."sv});
    }
    auto now = system_clock::now();
    if (req.timestamp > now + STORE_TOLERANCE || req.expiry < now - STORE_TOLERANCE) {
        OXEN_LOG(debug, "Forbidden. Invalid Timestamp: {}", to_epoch_ms(req.timestamp));
        return cb(Response{http::NOT_ACCEPTABLE, "Timestamp error: check your clock"sv});
    }

    // TODO: remove after HF 19
    if (!service_node_.hf_at_least(snode::HARDFORK_NAMESPACES) &&
        req.msg_namespace != namespace_id::Default)
        req.msg_namespace = namespace_id::Default;

    if (!is_public_namespace(req.msg_namespace)) {
        if (!req.signature) {
            auto err = fmt::format(
                    "store: signature required to store to namespace {}",
                    to_int(req.msg_namespace));
            OXEN_LOG(warn, err);
            return cb(Response{http::UNAUTHORIZED, err});
        }
        if (req.timestamp < now - SIGNATURE_TOLERANCE ||
            req.timestamp > now + SIGNATURE_TOLERANCE) {
            OXEN_LOG(
                    debug,
                    "store: invalid timestamp ({}s from now)",
                    duration_cast<seconds>(req.timestamp - now).count());
            return cb(
                    Response{http::NOT_ACCEPTABLE, "store timestamp too far from current time"sv});
        }
        if (!verify_signature(
                    req.pubkey,
                    req.pubkey_ed25519,
                    req.subkey,
                    *req.signature,
                    "store",
                    req.msg_namespace == namespace_id::Default ? "" : to_string(req.msg_namespace),
                    req.timestamp)) {
            OXEN_LOG(debug, "store: signature verification failed");
            return cb(Response{http::UNAUTHORIZED, "store signature verification failed"sv});
        }
    }

    bool entry_router = req.recurse == true;

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    std::string message_hash =
            computeMessageHash(req.timestamp, req.expiry, req.pubkey, req.msg_namespace, req.data);

    bool new_msg;
    bool success = false;
    try {
        success = service_node_.process_store(
                message{req.pubkey,
                        message_hash,
                        req.msg_namespace,
                        req.timestamp,
                        req.expiry,
                        std::move(req.data)},
                &new_msg);
    } catch (const std::exception& e) {
        OXEN_LOG(
                err,
                "Internal Server Error. Could not store message for {}: {}",
                obfuscate_pubkey(req.pubkey),
                e.what());
        mine["reason"] = e.what();
    }
    if (success) {
        mine["hash"] = message_hash;
        auto sig = create_signature(ed25519_sk_, message_hash);
        mine["signature"] =
                req.b64 ? oxenc::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
        if (!new_msg)
            mine["already"] = true;
        if (entry_router) {
            // Backwards compat: put the hash at top level, too.  TODO: remove eventually
            res->result["hash"] = message_hash;
            // No longer used, but here to avoid breaking older clients.  TODO: remove
            // eventually
            res->result["difficulty"] = 1;
        }
    } else {
        mine["failed"] = true;
        mine["query_failure"] = true;
    }
    if (entry_router) {
        // Deprecated: we accidentally set this one inside the entry router's "swarm" instead of in
        // the outer response, so keep it here for now in case something is relying on that:
        mine["t"] = to_epoch_ms(now);

        add_misc_response_fields(res->result, service_node_, now);
    }

    OXEN_LOG(
            trace,
            "Successfully stored message {}{} for {}",
            message_hash,
            req.msg_namespace != namespace_id::Default
                    ? fmt::format("[{}]", to_int(req.msg_namespace))
                    : "",
            obfuscate_pubkey(req.pubkey));

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(
        rpc::oxend_request&& req, std::function<void(rpc::Response)> cb) {
    std::optional<std::string> oxend_params;
    if (req.params)
        oxend_params = req.params->dump();

    service_node_.omq_server().oxend_request(
            "rpc." + req.endpoint,
            [cb = std::move(cb), this](bool success, auto&& data) {
                std::string err;
                // Currently we only support json endpoints; if we want to support non-json
                // endpoints (which end in ".bin") at some point in the future then we'll need to
                // return those endpoint results differently here.
                if (success && data.size() >= 2 && data[0] == "200") {
                    json result = json::parse(data[1], nullptr, false);
                    if (result.is_discarded()) {
                        OXEN_LOG(
                                warn,
                                "Invalid oxend response to client request: result is not valid "
                                "json");
                        return cb({http::BAD_GATEWAY, "oxend returned unparseable data"s});
                    }
                    json res{{"result", std::move(result)}};
                    add_misc_response_fields(res, service_node_);

                    return cb({http::OK, std::move(res)});
                }
                return cb(
                        {http::BAD_REQUEST,
                         data.size() >= 2 && !data[1].empty() ? std::move(data[1])
                                                              : "Unknown oxend error"s});
            },
            oxend_params);
}

void RequestHandler::process_client_req(
        rpc::get_swarm&& req, std::function<void(rpc::Response)> cb) {
    const auto swarm = service_node_.get_swarm(req.pubkey);

    OXEN_LOG(
            debug,
            "get swarm for {}, swarm size: {}",
            obfuscate_pubkey(req.pubkey),
            swarm.snodes.size());

    auto body = swarm_to_json(swarm);
    add_misc_response_fields(body, service_node_);

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "swarm details for pk {}: {}", obfuscate_pubkey(req.pubkey), body.dump());

    cb(Response{http::OK, std::move(body)});
}

void RequestHandler::process_client_req(
        rpc::retrieve&& req, std::function<void(rpc::Response)> cb) {
    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();

    // At HF19 start requiring authentication for all retrievals (except legacy closed groups, which
    // can't be authenticated for technical reasons).
    if (service_node_.hf_at_least(snode::HARDFORK_RETRIEVE_AUTH) &&
        req.msg_namespace != namespace_id::LegacyClosed) {
        if (!req.check_signature) {
            OXEN_LOG(debug, "retrieve: request signature required as of HF19.1");
            return cb(Response{http::UNAUTHORIZED, "retrieve: request signature required"sv});
        }
    }

    if (req.check_signature) {
        if (req.timestamp < now - SIGNATURE_TOLERANCE ||
            req.timestamp > now + SIGNATURE_TOLERANCE) {
            OXEN_LOG(
                    debug,
                    "retrieve: invalid timestamp ({}s from now)",
                    duration_cast<seconds>(req.timestamp - now).count());
            return cb(Response{
                    http::NOT_ACCEPTABLE, "retrieve timestamp too far from current time"sv});
        }
        if (!verify_signature(
                    req.pubkey,
                    req.pubkey_ed25519,
                    req.subkey,
                    req.signature,
                    "retrieve",
                    req.msg_namespace != namespace_id::Default
                            ? std::to_string(to_int(req.msg_namespace))
                            : ""s,
                    req.timestamp)) {
            OXEN_LOG(debug, "retrieve: signature verification failed");
            return cb(Response{http::UNAUTHORIZED, "retrieve signature verification failed"sv});
        }
    }

    std::vector<message> msgs;
    try {
        msgs = service_node_.get_db().retrieve(
                req.pubkey,
                req.msg_namespace,
                req.last_hash.value_or(""),
                CLIENT_RETRIEVE_MESSAGE_LIMIT);
        service_node_.record_retrieve_request();
    } catch (const std::exception& e) {
        auto msg = fmt::format(
                "Internal Server Error. Could not retrieve messages for {}",
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
                {"data", req.b64 ? oxenc::to_base64(msg.data) : std::move(msg.data)},
        });
    }

    json res{{"messages", std::move(messages)}};
    add_misc_response_fields(res, service_node_, now);

    return cb(Response{http::OK, std::move(res)});
}

void RequestHandler::process_client_req(rpc::info&&, std::function<void(rpc::Response)> cb) {
    return cb(Response{
            http::OK,
            json{{"version", STORAGE_SERVER_VERSION},
                 {"timestamp", to_epoch_ms(system_clock::now())}}});
}

namespace {
    template <typename... SigArgs>
    void handle_action_all_ns(
            nlohmann::json& mine,
            const std::string& mine_key,
            std::vector<std::pair<namespace_id, std::string>>&& affected,
            bool b64,
            SigArgs&&... signature_args) {

        std::sort(affected.begin(), affected.end(), [](const auto& a, const auto& b) {
            return a.second < b.second;
        });
        std::vector<std::string_view> sorted_hashes;
        sorted_hashes.reserve(affected.size());
        for (const auto& [ns, hash] : affected)
            sorted_hashes.emplace_back(hash);

        auto sig = create_signature(std::forward<SigArgs>(signature_args)..., sorted_hashes);
        mine["signature"] = b64 ? oxenc::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);

        // We've totally sorted by hash (for the signature, above), so this loop below will be
        // appending to the sublists in sorted order:
        auto& result = (mine[mine_key] = json::object());
        for (auto& [ns, hash] : affected)
            result[to_string(ns)].push_back(std::move(hash));
    }

    template <typename... SigArgs>
    void handle_action_one_ns(
            nlohmann::json& mine,
            const std::string& mine_key,
            std::vector<std::string>&& affected,
            bool b64,
            SigArgs&&... signature_args) {

        std::sort(affected.begin(), affected.end());
        auto sig = create_signature(std::forward<SigArgs>(signature_args)..., affected);
        mine["signature"] = b64 ? oxenc::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
        mine[mine_key] = std::move(affected);
    }
}  // namespace

void RequestHandler::process_client_req(
        rpc::delete_all&& req, std::function<void(rpc::Response)> cb) {
    OXEN_LOG(debug, "processing delete_all {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    const auto tolerance = req.recurse ? SIGNATURE_TOLERANCE : SIGNATURE_TOLERANCE_FORWARDED;
    if (req.timestamp < now - tolerance || req.timestamp > now + tolerance) {
        OXEN_LOG(
                debug,
                "delete_all: invalid timestamp ({}s from now)",
                duration_cast<seconds>(req.timestamp - now).count());
        return cb(
                Response{http::NOT_ACCEPTABLE, "delete_all timestamp too far from current time"sv});
    }

    if (!verify_signature(
                req.pubkey,
                req.pubkey_ed25519,
                std::nullopt,  // no subkey allowed
                req.signature,
                "delete_all",
                signature_value(req.msg_namespace),
                req.timestamp)) {
        OXEN_LOG(debug, "delete_all: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_all signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    if (is_all(req.msg_namespace)) {
        handle_action_all_ns(
                mine,
                "deleted",
                service_node_.get_db().delete_all(req.pubkey),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.timestamp);

    } else {
        handle_action_one_ns(
                mine,
                "deleted",
                service_node_.get_db().delete_all(req.pubkey, var::get<namespace_id>(req.msg_namespace)),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.timestamp);
    }

    if (req.recurse)
        add_misc_response_fields(res->result, service_node_, now);

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(rpc::delete_msgs&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing delete_msgs {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    if (!verify_signature(
                req.pubkey,
                req.pubkey_ed25519,
                std::nullopt,  // no subkey allowed
                req.signature,
                "delete",
                req.messages)) {
        OXEN_LOG(debug, "delete_msgs: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_msgs signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    auto deleted = service_node_.get_db().delete_by_hash(req.pubkey, req.messages);
    std::sort(deleted.begin(), deleted.end());
    auto sig = create_signature(ed25519_sk_, req.pubkey.prefixed_hex(), req.messages, deleted);
    mine["deleted"] = std::move(deleted);
    mine["signature"] = req.b64 ? oxenc::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    if (req.recurse)
        add_misc_response_fields(res->result, service_node_);

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
        OXEN_LOG(
                debug,
                "delete_before: invalid timestamp ({}s from now)",
                duration_cast<seconds>(req.before - now).count());
        return cb(Response{http::UNAUTHORIZED, "delete_before timestamp too far in the future"sv});
    }

    if (!verify_signature(
                req.pubkey,
                req.pubkey_ed25519,
                std::nullopt,  // no subkey allowed
                req.signature,
                "delete_before",
                signature_value(req.msg_namespace),
                req.before)) {
        OXEN_LOG(debug, "delete_before: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "delete_before signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    if (is_all(req.msg_namespace)) {
        handle_action_all_ns(
                mine,
                "deleted",
                service_node_.get_db().delete_by_timestamp(req.pubkey, req.before),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.before);

    } else {
        handle_action_one_ns(
                mine,
                "deleted",
                service_node_.get_db().delete_by_timestamp(
                        req.pubkey, var::get<namespace_id>(req.msg_namespace), req.before),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.before);
    }
    if (req.recurse)
        add_misc_response_fields(res->result, service_node_, now);

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(rpc::expire_all&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing expire_all {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.expiry < now - (req.recurse ? SIGNATURE_TOLERANCE : SIGNATURE_TOLERANCE_FORWARDED)) {
        OXEN_LOG(
                debug,
                "expire_all: invalid timestamp ({}s ago)",
                duration_cast<seconds>(now - req.expiry).count());
        return cb(
                Response{http::NOT_ACCEPTABLE, "expire_all timestamp should be >= current time"sv});
    }

    if (!verify_signature(
                req.pubkey,
                req.pubkey_ed25519,
                std::nullopt,  // no subkey allowed
                req.signature,
                "expire_all",
                signature_value(req.msg_namespace),
                req.expiry)) {
        OXEN_LOG(debug, "expire_all: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "expire_all signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    if (is_all(req.msg_namespace)) {
        handle_action_all_ns(
                mine,
                "updated",
                service_node_.get_db().update_all_expiries(req.pubkey, req.expiry),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.expiry);
    } else {
        handle_action_one_ns(
                mine,
                "updated",
                service_node_.get_db().update_all_expiries(
                        req.pubkey, var::get<namespace_id>(req.msg_namespace), req.expiry),
                req.b64,
                ed25519_sk_,
                req.pubkey.prefixed_hex(),
                req.expiry);
    }
    if (req.recurse)
        add_misc_response_fields(res->result, service_node_, now);

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}
void RequestHandler::process_client_req(rpc::expire_msgs&& req, std::function<void(Response)> cb) {
    OXEN_LOG(debug, "processing expire_msgs {} request", req.recurse ? "direct" : "forwarded");

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto now = system_clock::now();
    if (req.expiry < now - 1min) {
        OXEN_LOG(
                debug,
                "expire_all: invalid timestamp ({}s ago)",
                duration_cast<seconds>(now - req.expiry).count());
        return cb(Response{http::UNAUTHORIZED, "expire_all timestamp should be >= current time"sv});
    }

    if (!verify_signature(
                req.pubkey,
                req.pubkey_ed25519,
                std::nullopt,  // no subkey allowed
                req.signature,
                "expire",
                req.expiry,
                req.messages)) {
        OXEN_LOG(debug, "expire_msgs: signature verification failed");
        return cb(Response{http::UNAUTHORIZED, "expire_msgs signature verification failed"sv});
    }

    auto [res, lock] = setup_recursive_request(service_node_, req, std::move(cb));

    // If we're recursive then put our stuff inside "swarm" alongside all the other results,
    // otherwise keep it top-level
    auto& mine = req.recurse
                       ? res->result["swarm"][service_node_.own_address().pubkey_ed25519.hex()]
                       : res->result;

    auto updated = service_node_.get_db().update_expiry(req.pubkey, req.messages, req.expiry);
    std::sort(updated.begin(), updated.end());
    auto sig = create_signature(
            ed25519_sk_, req.pubkey.prefixed_hex(), req.expiry, req.messages, updated);
    mine["updated"] = std::move(updated);
    mine["signature"] = req.b64 ? oxenc::to_base64(sig.begin(), sig.end()) : util::view_guts(sig);
    if (req.recurse)
        add_misc_response_fields(res->result, service_node_, now);

    if (--res->pending == 0)
        reply_or_fail(std::move(res));
}

void RequestHandler::process_client_req(rpc::batch&& req, std::function<void(rpc::Response)> cb) {

    auto subresults = std::make_shared<json>(json::array());
    for (size_t i = 0; i < req.subreqs.size(); i++)
        subresults->emplace_back();

    for (size_t i = 0; i < req.subreqs.size(); i++) {
        auto handler = [subresults, i, cb](Response r) {
            json& subres = (*subresults)[i];
            subres["code"] = r.status.first;
            if (auto* j = std::get_if<json>(&r.body))
                subres["body"] = std::move(*j);
            else
                subres["body"] = std::string{view_body(r)};
            bool done = true;
            for (auto& sr : *subresults)
                if (sr.is_null()) {
                    done = false;
                    break;
                }
            if (done)
                cb(Response{http::OK, json({{"results", std::move(*subresults)}})});
        };
        std::visit(
                [this, handler = std::move(handler)](auto&& s) {
                    process_client_req(std::move(s), std::move(handler));
                },
                req.subreqs[i]);
    }
}

namespace {
    struct sequence_manager {
        std::vector<client_subrequest> subreqs;
        json subresults = json::array();
        std::function<void(Response r)> subresult_callback;
    };
}  // namespace

void RequestHandler::process_client_req(
        rpc::sequence&& req, std::function<void(rpc::Response)> cb) {

    if (req.subreqs.empty()) {
        cb(Response{http::OK, json({{"results", json::array()}})});
        return;
    }

    auto manager = std::make_shared<sequence_manager>();
    manager->subreqs = std::move(req.subreqs);
    manager->subresult_callback = [this, manager, cb = std::move(cb)](Response r) {
        json& subres = manager->subresults.emplace_back();
        auto status = r.status.first;
        subres["code"] = status;
        if (auto* j = std::get_if<json>(&r.body))
            subres["body"] = std::move(*j);
        else
            subres["body"] = std::string{view_body(r)};

        if (status < 200 || status > 299 || manager->subresults.size() >= manager->subreqs.size()) {
            manager->subresult_callback = nullptr;
            cb(Response{http::OK, json({{"results", std::move(manager->subresults)}})});
        } else {
            // subrequest was successful and we're not done, so fire off the next one
            std::visit(
                    [&](auto&& subreq) {
                        process_client_req(std::move(subreq), manager->subresult_callback);
                    },
                    manager->subreqs[manager->subresults.size()]);
        }
    };

    std::visit(
            [&](auto&& subreq) {
                process_client_req(std::move(subreq), manager->subresult_callback);
            },
            manager->subreqs[0]);
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
        std::string_view method_name, json params, std::function<void(Response)> cb) {
    if (auto it = client_rpc_endpoints.find(method_name); it != client_rpc_endpoints.end()) {
        OXEN_LOG(debug, "Process client request: {}", method_name);
        try {
            return it->second.http_json(*this, std::move(params), cb);
        } catch (const rpc::parse_error& e) {
            // These exceptions carry a failure message to send back to the client
            OXEN_LOG(debug, "Invalid request: {}", e.what());
            return cb(Response{http::BAD_REQUEST, "invalid request: "s + e.what()});
        } catch (const std::exception& e) {
            // Other exceptions might contain something sensitive or irrelevant so warn about it
            // and send back a generic message.
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
        msgs = service_node_.get_db().retrieve_all();
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
        crypto::legacy_pubkey tester,
        std::string msg_hash_hex,
        std::function<void(snode::MessageTestStatus, std::string, steady_clock::duration)>
                callback) {
    /// TODO: we never actually test that `height` is within any reasonable
    /// time window (or that it is not repeated multiple times), we should do
    /// that! This is done implicitly to some degree using
    /// `block_hashes_cache_`, which holds a limited number of recent blocks
    /// only and fails if an earlier block is requested

    auto started = steady_clock::now();
    auto [status, answer] = service_node_.process_storage_test_req(height, tester, msg_hash_hex);

    if (status == snode::MessageTestStatus::RETRY) {
        // Our first attempt returned a RETRY, so set up a timer to keep retrying

        auto timer = std::make_shared<oxenmq::TimerID>();
        auto& timer_ref = *timer;
        service_node_.omq_server()->add_timer(
                timer_ref,
                [this,
                 timer = std::move(timer),
                 height,
                 tester,
                 hash = std::move(msg_hash_hex),
                 started,
                 callback = std::move(callback)] {
                    auto elapsed = steady_clock::now() - started;

                    OXEN_LOG(
                            trace,
                            "Performing storage test retry, {} since started",
                            util::friendly_duration(elapsed));

                    auto [status, answer] =
                            service_node_.process_storage_test_req(height, tester, hash);
                    if (status == snode::MessageTestStatus::RETRY && elapsed < TEST_RETRY_PERIOD &&
                        !service_node_.shutting_down())
                        return;  // Still retrying so wait for the next call
                    service_node_.omq_server()->cancel_timer(*timer);
                    callback(status, std::move(answer), elapsed);
                },
                TEST_RETRY_INTERVAL);
    } else {
        callback(status, std::move(answer), steady_clock::now() - started);
    }
}

Response RequestHandler::wrap_proxy_response(
        Response res,
        const crypto::x25519_pubkey& client_key,
        crypto::EncryptType enc_type,
        bool embed_json,
        bool base64) const {
    int status = res.status.first;
    std::string body;
    if (std::holds_alternative<std::string>(res.body))
        body = json{{"status", status}, {"body", std::move(std::get<std::string>(res.body))}}
                       .dump();
    else if (std::holds_alternative<std::string_view>(res.body))
        body = json{{"status", status}, {"body", std::get<std::string_view>(res.body)}}.dump();
    else if (embed_json)
        body = json{{"status", status}, {"body", std::move(std::get<json>(res.body))}}.dump();
    else  // Yuck: double-encoded json
        body = json{{"status", status}, {"body", std::get<json>(res.body).dump()}}.dump();

    std::string ciphertext = channel_cipher_.encrypt(enc_type, body, client_key);
    if (base64)
        ciphertext = oxenc::to_base64(std::move(ciphertext));

    return Response{http::OK, std::move(ciphertext)};
}

void RequestHandler::process_onion_req(std::string_view ciphertext, OnionRequestMetadata data) {
    if (!service_node_.snode_ready())
        return data.cb(
                {http::SERVICE_UNAVAILABLE,
                 fmt::format("Snode not ready: {}", service_node_.own_address().pubkey_ed25519)});

    OXEN_LOG(debug, "process_onion_req");

    service_node_.record_onion_request();

    var::visit(
            [&](auto&& x) { process_onion_req(std::move(x), std::move(data)); },
            process_ciphertext_v2(channel_cipher_, ciphertext, data.ephem_key, data.enc_type));
}

void RequestHandler::process_onion_req(FinalDestinationInfo&& info, OnionRequestMetadata&& data) {
    OXEN_LOG(debug, "We are the target of the onion request!");

    if (!service_node_.snode_ready())
        return data.cb(wrap_proxy_response(
                {http::SERVICE_UNAVAILABLE, "Snode not ready"s},
                data.ephem_key,
                data.enc_type,
                info.json,
                info.base64));

    process_client_req(
            info.body,
            [this, data = std::move(data), json = info.json, b64 = info.base64](rpc::Response res) {
                data.cb(wrap_proxy_response(
                        std::move(res), data.ephem_key, data.enc_type, json, b64));
            });
}

void RequestHandler::process_onion_req(RelayToNodeInfo&& info, OnionRequestMetadata&& data) {
    auto& [payload, ekey, etype, dest] = info;

    auto dest_node = service_node_.find_node(dest);
    if (!dest_node) {
        auto msg = fmt::format("Next node not found: {}", dest);
        OXEN_LOG(warn, "{}", msg);
        return data.cb({http::BAD_GATEWAY, std::move(msg)});
    }

    auto on_response = [cb = std::move(data.cb)](bool success, std::vector<std::string> data) {
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
            OXEN_LOG(
                    debug,
                    "Onion request relay failed with: {}",
                    std::holds_alternative<nlohmann::json>(res.body) ? "<json>" : view_body(res));

        cb(std::move(res));
    };

    OXEN_LOG(debug, "send_onion_to_sn, sn: {}", dest_node->pubkey_legacy);

    data.ephem_key = ekey;
    data.enc_type = etype;
    service_node_.send_onion_to_sn(
            *dest_node, std::move(payload), std::move(data), std::move(on_response));
}

void RequestHandler::process_onion_req(RelayToServerInfo&& info, OnionRequestMetadata&& data) {
    OXEN_LOG(debug, "We are to forward the request to url: {}{}", info.host, info.target);

    // Forward the request to url but only if it ends in `/lsrpc`
    if (!(info.protocol == "http" || info.protocol == "https") ||
        !is_onion_url_target_allowed(info.target))
        return data.cb(wrap_proxy_response(
                {http::BAD_REQUEST, "Invalid url"s}, data.ephem_key, data.enc_type));

    std::string urlstr;
    urlstr.reserve(
            info.protocol.size() + 3 + info.host.size() + 6 /*:port*/ + 1 + info.target.size());
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

    pending_proxy_requests_.emplace_front(cpr::PostCallback(
            [&omq = *service_node_.omq_server(), cb = std::move(data.cb)](cpr::Response r) {
                Response res;
                if (r.error.code != cpr::ErrorCode::OK) {
                    OXEN_LOG(
                            debug,
                            "Onion proxied request to {} failed: {}",
                            r.url.str(),
                            r.error.message);
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
            cpr::Header{
                    {"User-Agent",
                     "Oxen Storage Server/" + std::string{STORAGE_SERVER_VERSION_STRING}},
                    {"Content-Type", "application/octet-stream"}},
            cpr::Timeout{ONION_URL_TIMEOUT},
            cpr::Ssl(cpr::ssl::TLSv1_2{}),
            cpr::Redirect{0L},
            cpr::Body{std::move(info.payload)}));
}

void RequestHandler::process_onion_req(
        ProcessCiphertextError&& error, OnionRequestMetadata&& data) {
    switch (error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT:
            return data.cb({http::BAD_REQUEST, "Invalid ciphertext"s});
        case ProcessCiphertextError::INVALID_JSON:
            return data.cb(wrap_proxy_response(
                    {http::BAD_REQUEST, "Invalid json"s}, data.ephem_key, data.enc_type));
    }
}

}  // namespace oxen::rpc
