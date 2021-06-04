#include "request_handler.h"
#include "channel_encryption.hpp"
#include "client_rpc_endpoints.h"
#include "http.h"
#include "omq_server.h"
#include "oxen_logger.h"
#include "signature.h"
#include "service_node.h"
#include "string_utils.hpp"
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

json snodes_to_json(const std::vector<sn_record_t>& snodes) {

    json res_body;
    json snodes_json = json::array();

    for (const auto& sn : snodes) {
        snodes_json.push_back(json{
                {"address", oxenmq::to_base32z(sn.pubkey_legacy.view()) + ".snode"}, // Deprecated, use pubkey_legacy instead
                {"pubkey_legacy", sn.pubkey_legacy.hex()},
                {"pubkey_x25519", sn.pubkey_x25519.hex()},
                {"pubkey_ed25519", sn.pubkey_ed25519.hex()},
                {"port", std::to_string(sn.port)}, // Why is this a string?
                {"ip", sn.ip}});
    }

    res_body["snodes"] = std::move(snodes_json);

    return res_body;
}

std::string obfuscate_pubkey(const user_pubkey_t& pk) {
    auto& pk_str = pk.str();
    if (pk_str.empty())
        return "(none)";
    std::string res;
    res += pk_str.substr(0, 4);
    res += u8"…";
    res += pk_str.substr(pk_str.length() - 3);
    return res;
}

template <typename RPC>
void register_client_rpc_endpoint(RequestHandler::rpc_map& regs) {
    auto call = [](RequestHandler& h, const json& params, std::function<void(Response)> cb) {
        RPC req;
        req.load_from(params);
        if constexpr (std::is_base_of_v<rpc::recursive, RPC>)
            req.recurse = true; // Requests through json are *always* client requests, so always recurse
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

} // anon. namespace

const RequestHandler::rpc_map RequestHandler::client_rpc_endpoints =
    register_client_rpc_endpoints(rpc::client_rpc_types{});

std::string computeMessageHash(std::vector<std::string_view> parts) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    for (const auto& s : parts)
        SHA512_Update(&ctx, s.data(), s.size());

    std::array<unsigned char, SHA512_DIGEST_LENGTH> result;
    SHA512_Final(result.data(), &ctx);
    return oxenmq::to_hex(result.begin(), result.end());
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
        const ChannelEncryption& ce)
    : service_node_{sn}, channel_cipher_(ce) {

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
        snodes_to_json(service_node_.get_snodes_by_pk(pubKey))};
}

void RequestHandler::process_client_req(
        rpc::store&& req, std::function<void(Response)> cb) {

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "Storing message: {}", oxenmq::to_base64(req.data));

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    auto ttl = duration_cast<milliseconds>(req.expiry - req.timestamp);
    if (!validateTTL(ttl)) {
        OXEN_LOG(warn, "Forbidden. Invalid TTL: {}ms", ttl.count());
        return cb(Response{http::FORBIDDEN, "Provided expiry/TTL is not valid."sv});
    }
    if (!validateTimestamp(req.timestamp, req.expiry)) {
        OXEN_LOG(debug, "Forbidden. Invalid Timestamp: {}",
                duration_cast<milliseconds>(req.timestamp.time_since_epoch()).count());
        return cb(Response{http::NOT_ACCEPTABLE, "Timestamp error: check your clock"sv});
    }

    auto messageHash = computeMessageHash(req.timestamp, req.expiry, req.pubkey.str(), req.data);

    bool success;
    try {
        success = service_node_.process_store(message_t{req.pubkey.str(), std::move(req.data), messageHash, req.timestamp, req.expiry});
    } catch (const std::exception& e) {
        OXEN_LOG(critical, "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(req.pubkey));
        return cb(Response{http::INTERNAL_SERVER_ERROR, std::string{e.what()}});
    }

    if (!success) {
        OXEN_LOG(warn, "Service node is initializing");
        return cb(Response{http::SERVICE_UNAVAILABLE, "Service node is initializing"sv});
    }

    OXEN_LOG(trace, "Successfully stored message {} for {}", messageHash, obfuscate_pubkey(req.pubkey));

    json res_body{
        {"hash", messageHash},
        {"difficulty", 1}, // No longer used, but here to avoid breaking older clients.  TODO: remove eventually
    };

    cb(Response{http::OK, std::move(res_body)});
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

    const auto nodes = service_node_.get_snodes_by_pk(req.pubkey);

    OXEN_LOG(debug, "get swarm for {}, swarm size: {}", obfuscate_pubkey(req.pubkey), nodes.size());

    auto body = snodes_to_json(nodes);

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "swarm details for pk {}: {}", obfuscate_pubkey(req.pubkey), body.dump());

    cb(Response{http::OK, std::move(body)});
}

void RequestHandler::process_client_req(
        rpc::retrieve&& req, std::function<void(oxen::Response)> cb) {

    if (!service_node_.is_pubkey_for_us(req.pubkey))
        return cb(handle_wrong_swarm(req.pubkey));

    std::vector<storage::Item> items;

    if (!service_node_.retrieve(req.pubkey.str(), req.last_hash.value_or(""), items)) {
        auto msg = fmt::format("Internal Server Error. Could not retrieve messages for {}",
                obfuscate_pubkey(req.pubkey));
        OXEN_LOG(critical, msg);
        return cb(Response{http::INTERNAL_SERVER_ERROR, std::move(msg)});
    }

    OXEN_LOG(trace, "Retrieved {} messages for {}", items.size(), obfuscate_pubkey(req.pubkey));

    json messages = json::array();
    for (const auto& item : items) {
        messages.push_back(json{
            {"hash", item.hash},
            {"expiration", duration_cast<milliseconds>(item.expiration.time_since_epoch()).count()},
            {"data", req.b64 ? oxenmq::to_base64(item.data) : std::move(item.data)},
        });
    }

    json body{
        {"messages", std::move(messages)}
    };

    return cb(Response{http::OK, std::move(body)});
}

void RequestHandler::process_client_req(
        rpc::info&&, std::function<void(oxen::Response)> cb) {

    return cb(Response{http::OK,
        json{
            {"version", STORAGE_SERVER_VERSION},
            {"timestamp",
                duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()},
        }});
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

    std::vector<storage::Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res)
        return {http::INTERNAL_SERVER_ERROR, "could not retrieve all entries"s};

    json messages = json::array();
    for (auto& entry : all_entries)
        messages.push_back({ {"data", entry.data}, {"pk", entry.pub_key} });

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
    if (std::holds_alternative<std::string_view>(res.body))
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
