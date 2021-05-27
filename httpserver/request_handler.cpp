#include "request_handler.h"
#include "channel_encryption.hpp"
#include "http_connection.h"
#include "omq_server.h"
#include "oxen_logger.h"
#include "signature.h"
#include "service_node.h"
#include "string_utils.hpp"
#include "utils.hpp"

#include "https_client.h"

#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>

using nlohmann::json;

namespace oxen {

std::string to_string(const Response& res) {

    std::stringstream ss;

    ss << "Status: " << res.status.first << " " << res.status.second
        << ", Content-Type: " << (res.content_type.empty() ? "(unspecified)" : res.content_type)
        << ", Body: <" << res.body << ">";

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

std::string obfuscate_pubkey(std::string_view pk) {
    std::string res;
    res += pk.substr(0, 2);
    res += "...";
    res += pk.substr(pk.length() - 3);
    return res;
}

} // anon. namespace


std::string computeMessageHash(std::vector<std::string_view> parts, bool hex) {
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    for (const auto& s : parts)
        SHA512_Update(&ctx, s.data(), s.size());

    std::string hashResult;
    hashResult.resize(SHA512_DIGEST_LENGTH);
    SHA512_Final(reinterpret_cast<unsigned char*>(hashResult.data()), &ctx);
    if (hex)
        hashResult = oxenmq::to_hex(hashResult);
    return hashResult;
}


RequestHandler::RequestHandler(
        ServiceNode& sn,
        const ChannelEncryption& ce)
    : service_node_{sn}, channel_cipher_(ce) {}

Response RequestHandler::handle_wrong_swarm(const user_pubkey_t& pubKey) {

    OXEN_LOG(trace, "Got client request to a wrong swarm");

    return {
        http::MISDIRECTED_REQUEST,
        snodes_to_json(service_node_.get_snodes_by_pk(pubKey)).dump(),
        http::json};
}

Response RequestHandler::process_store(const json& params) {

    for (const auto& field : {"pubKey", "ttl", "timestamp", "data"}) {
        if (!params.contains(field)) {
            OXEN_LOG(debug, "Bad client request: no `{}` field", field);
            return {
                http::BAD_REQUEST,
                fmt::format("invalid json: no `{}` field\n", field)};
        }
    }

    const auto& ttl = params.at("ttl").get_ref<const std::string&>();
    const auto& timestamp =
        params.at("timestamp").get_ref<const std::string&>();
    const auto& data = params.at("data").get_ref<const std::string&>();

    OXEN_LOG(trace, "Storing message: {}", data);

    bool created;
    auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), created);

    if (!created) {
        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        OXEN_LOG(debug, "{}", msg);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        OXEN_LOG(debug, "Message body too long: {}", data.size());

        auto msg =
            fmt::format("Message body exceeds maximum allowed length of {}\n",
                        MAX_MESSAGE_BODY);
        return {http::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        OXEN_LOG(debug, "Forbidden. Invalid TTL: {}", ttl);
        return {http::FORBIDDEN, "Provided TTL is not valid.\n"};
    }

    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        OXEN_LOG(debug, "Forbidden. Invalid Timestamp: {}", timestamp);
        return {http::NOT_ACCEPTABLE, "Timestamp error: check your clock\n"};
    }

    auto messageHash = computeMessageHash({timestamp, ttl, pk.str(), data}, true);

    bool success;

    try {
        success = service_node_.process_store({pk.str(), data, messageHash, ttlInt, timestampInt});
    } catch (const std::exception& e) {
        OXEN_LOG(critical,
                 "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pk.str()));
        return {http::INTERNAL_SERVER_ERROR, e.what()};
    }

    if (!success) {

        OXEN_LOG(warn, "Service node is initializing");
        return {http::SERVICE_UNAVAILABLE,
            "Service node is initializing\n"};
    }

    OXEN_LOG(trace, "Successfully stored message for {}",
             obfuscate_pubkey(pk.str()));

    json res_body;
    /// NOTE: difficulty is not longer used by modern clients, but
    /// we send this to avoid breaking older clients.
    res_body["difficulty"] = 1;

    return {http::OK, res_body.dump(), http::json};
}

inline const static std::unordered_set<std::string> allowed_oxend_endpoints{{
    "get_service_nodes"s, "ons_resolve"s}};

void RequestHandler::process_oxend_request(
    const json& params, std::function<void(oxen::Response)> cb) {

    std::string endpoint;
    if (auto it = params.find("endpoint");
            it == params.end() || !it->is_string())
        return cb({http::BAD_REQUEST, "missing 'endpoint'"});
    else
        endpoint = it->get<std::string>();

    if (!allowed_oxend_endpoints.count(endpoint))
        return cb({http::BAD_REQUEST, "Endpoint not allowed: " + endpoint});

    std::optional<std::string> oxend_params;
    if (auto it = params.find("params"); it != params.end()) {
        if (!it->is_object())
            return cb({http::BAD_REQUEST, "invalid oxend 'params' argument"});
        oxend_params = it->dump();
    }

    service_node_.omq_server().oxend_request(
        "rpc." + endpoint,
        [cb = std::move(cb)](bool success, auto&& data) {
            std::string err;
            // Currently we only support json endpoints; if we want to support non-json endpoints
            // (which end in ".bin") at some point in the future then we'll need to return those
            // endpoint results differently here.
            if (success && data.size() >= 2 && data[0] == "200")
                return cb({http::OK,
                    R"({"result":)" + std::move(data[1]) + "}",
                    http::json});
            return cb({http::BAD_REQUEST,
                data.size() >= 2 && !data[1].empty()
                    ? std::move(data[1]) : "Unknown oxend error"s});
        },
        oxend_params);
}

Response RequestHandler::process_retrieve_all() {

    std::vector<storage::Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res) {
        return Response{http::INTERNAL_SERVER_ERROR,
                        "could not retrieve all entries\n"};
    }

    json messages = json::array();

    for (auto& entry : all_entries) {
        json item;
        item["data"] = entry.data;
        item["pk"] = entry.pub_key;
        messages.push_back(item);
    }

    json res_body;
    res_body["messages"] = messages;

    return Response{http::OK, res_body.dump(), http::json};
}

Response RequestHandler::process_snodes_by_pk(const json& params) const {

    auto it = params.find("pubKey");
    if (it == params.end()) {
        OXEN_LOG(debug, "Bad client request: no `pubKey` field");
        return {http::BAD_REQUEST,
                        "invalid json: no `pubKey` field\n"};
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), success);
    if (!success) {

        auto msg = fmt::format("Pubkey must be {} hex digits long\n",
                               get_user_pubkey_size());
        OXEN_LOG(debug, "{}", msg);
        return Response{http::BAD_REQUEST, std::move(msg)};
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pk);

    OXEN_LOG(debug, "Snodes by pk size: {}", nodes.size());

    const json res_body = snodes_to_json(nodes);

    OXEN_LOG(debug, "Snodes by pk: {}", res_body.dump());

    return Response{http::OK, res_body.dump(), http::json};
}

Response RequestHandler::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            auto msg = fmt::format("invalid json: no `{}` field", field);
            OXEN_LOG(debug, "{}", msg);
            return Response{http::BAD_REQUEST, std::move(msg)};
        }
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);

    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        OXEN_LOG(debug, "{}", msg);
        return Response{http::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    const std::string& last_hash =
        params.at("lastHash").get_ref<const std::string&>();

    // Note: We removed long-polling

    std::vector<storage::Item> items;

    if (!service_node_.retrieve(pk.str(), last_hash, items)) {

        auto msg = fmt::format(
            "Internal Server Error. Could not retrieve messages for {}",
            obfuscate_pubkey(pk.str()));
        OXEN_LOG(critical, "{}", msg);

        return Response{http::INTERNAL_SERVER_ERROR, std::move(msg)};
    }

    if (!items.empty()) {
        OXEN_LOG(trace, "Successfully retrieved messages for {}",
                 obfuscate_pubkey(pk.str()));
    }

    json res_body;
    json messages = json::array();

    for (const auto& item : items) {
        json message;
        message["hash"] = item.hash;
        /// TODO: calculate expiration time once only?
        message["expiration"] = item.timestamp + item.ttl;
        message["data"] = item.data;
        messages.push_back(message);
    }

    res_body["messages"] = messages;

    return Response{http::OK, res_body.dump(), http::json};
}

void RequestHandler::process_client_req(
    std::string_view req_json, std::function<void(oxen::Response)> cb) {

    OXEN_LOG(trace, "process_client_req str <{}>", req_json);

    const json body = json::parse(req_json, nullptr, false);
    if (body.is_discarded()) {
        OXEN_LOG(debug, "Bad client request: invalid json");
        return cb(Response{http::BAD_REQUEST, "invalid json\n"});
    }

    if (OXEN_LOG_ENABLED(trace))
        OXEN_LOG(trace, "process_client_req json <{}>", body.dump(2));

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        OXEN_LOG(debug, "Bad client request: no method field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `method` field\n"});
    }

    const auto& method_name = method_it->get_ref<const std::string&>();

    OXEN_LOG(trace, "  - method name: {}", method_name);

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        OXEN_LOG(debug, "Bad client request: no params field");
        return cb(Response{http::BAD_REQUEST, "invalid json: no `params` field\n"});
    }

    if (method_name == "store") {
        OXEN_LOG(debug, "Process client request: store");
        return cb(process_store(*params_it));
    }
    if (method_name == "retrieve") {
        OXEN_LOG(debug, "Process client request: retrieve");
        return cb(process_retrieve(*params_it));
        // TODO: maybe we should check if (some old) clients requests
        // long-polling and then wait before responding to prevent spam

    }
    if (method_name == "get_snodes_for_pubkey") {
        OXEN_LOG(debug, "Process client request: snodes for pubkey");
        return cb(process_snodes_by_pk(*params_it));
    }
    if (method_name == "oxend_request") {
        OXEN_LOG(debug, "Process client request: oxend_request");
        return process_oxend_request(*params_it, std::move(cb));
    }
    if (method_name == "get_lns_mapping") {
        const auto name_it = params_it->find("name_hash");
        if (name_it == params_it->end())
            return cb({http::BAD_REQUEST, "Field <name_hash> is missing"});
        return process_lns_request(*name_it, std::move(cb));
    }

    OXEN_LOG(debug, "Bad client request: unknown method '{}'", method_name);
    return cb({http::BAD_REQUEST, "no method " + method_name});
}

std::variant<legacy_pubkey, Response> RequestHandler::validate_snode_signature(const Request& r, bool headers_only) {
    legacy_pubkey pubkey;
    if (auto it = r.headers.find(http::SNODE_SENDER_HEADER); it != r.headers.end())
        pubkey = parse_legacy_pubkey(it->second);
    if (!pubkey) {
        OXEN_LOG(debug, "Missing or invalid pubkey header for request");
        return Response{http::BAD_REQUEST, "missing/invalid pubkey header"};
    }
    signature sig;
    if (auto it = r.headers.find(http::SNODE_SIGNATURE_HEADER); it != r.headers.end()) {
        try { sig = signature::from_base64(it->second); }
        catch (...) {
            OXEN_LOG(warn, "invalid signature (not b64) found in header from {}", pubkey);
            return Response{http::BAD_REQUEST, "Invalid signature"};
        }
    } else {
        OXEN_LOG(debug, "Missing required signature header for request");
        return Response{http::BAD_REQUEST, "missing signature header"};
    }

    if (!service_node_.find_node(pubkey)) {
        OXEN_LOG(debug, "Rejecting signature from unknown service node: {}", pubkey);
        return Response{http::UNAUTHORIZED, "Unknown service node"};
    }

    if (!headers_only) {
        if (!check_signature(sig, hash_data(r.body), pubkey)) {
            OXEN_LOG(debug, "snode signature verification failed for pubkey {}", pubkey);
            return Response{http::UNAUTHORIZED, "snode signature verification failed"};
        }
    }
    return pubkey;
}

Response RequestHandler::wrap_proxy_response(Response res,
                                             const x25519_pubkey& client_key,
                                             EncryptType enc_type,
                                             bool embed_json,
                                             bool base64) const {

    int status = res.status.first;
    std::string body;
    if (embed_json && res.content_type == http::json)
        body = fmt::format(R"({{"status":{},"body":{}}})", status, res.body);
    else
        body = json{{"status", status}, {"body", res.body}}.dump();

    std::string ciphertext = channel_cipher_.encrypt(enc_type, body, client_key);
    if (base64)
        ciphertext = oxenmq::to_base64(std::move(ciphertext));

    // why does this have to be json???
    return Response{http::OK, std::move(ciphertext), http::json};
}

void RequestHandler::process_lns_request(
    std::string name_hash, std::function<void(oxen::Response)> cb) {

    json params;
    json array = json::array();
    json entry;

    entry["name_hash"] = std::move(name_hash);

    json types = json::array();
    types.push_back(0);
    entry["types"] = types;

    array.push_back(entry);
    params["entries"] = array;

#ifdef INTEGRATION_TEST
    // use mainnet seed
    oxend_json_rpc_request(
        service_node_.ioc(), "public.loki.foundation", 22023, "lns_names_to_owners", params,
        [cb = std::move(cb)](sn_response_t sn) {
            if (sn.error_code == SNodeError::NO_ERROR && sn.body)
                cb({http::OK, *sn.body});
            else
                cb({http::BAD_REQUEST, "unknown oxend error"});
        });
#else
    service_node_.omq_server().oxend_request(
        "rpc.lns_names_to_owners",
        [cb = std::move(cb)](bool success, auto&& data) {
            if (success && !data.empty())
                cb({http::OK, data.front()});
            else
                cb({http::BAD_REQUEST, "unknown oxend error"});
        });
#endif
}

void RequestHandler::process_onion_req(std::string_view ciphertext,
                                       OnionRequestMetadata data) {
    if (!service_node_.snode_ready())
        return data.cb({
            http::SERVICE_UNAVAILABLE,
            fmt::format("Snode not ready: {}", service_node_.own_address().pubkey_ed25519)});

    OXEN_LOG(debug, "process_onion_req");

    var::visit([&](auto&& x) { process_onion_req(std::move(x), std::move(data)); },
            process_ciphertext_v2(channel_cipher_, ciphertext, data.ephem_key, data.enc_type));
}

void RequestHandler::process_onion_req(FinalDestinationInfo&& info,
        OnionRequestMetadata&& data) {
    OXEN_LOG(debug, "We are the final destination in the onion request!");

    process_onion_exit(
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
            return cb({http::GATEWAY_TIMEOUT, "Request time out"});
        }

        // We expect a two-part message, but for forwards compatibility allow extra parts
        if (data.size() < 2) {
            OXEN_LOG(debug, "[Onion request] Invalid response; expected at least 2 parts");
            return cb({http::INTERNAL_SERVER_ERROR, "Invalid response from snode"});
        }

        Response res{http::INTERNAL_SERVER_ERROR, std::move(data[1]), http::json};
        if (int code; util::parse_int(data[0], code))
            res.status = http::from_code(code);

        /// We use http status codes (for now)
        if (res.status != http::OK)
            OXEN_LOG(debug, "Onion request relay failed with: {}", res.body);

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
    if (is_onion_url_target_allowed(info.target))
        return process_onion_to_url(info.protocol, std::move(info.host), info.port,
                std::move(info.target), std::move(info.payload), std::move(data.cb));

    return data.cb(wrap_proxy_response({http::BAD_REQUEST, "Invalid url"},
            data.ephem_key, data.enc_type));
}

void RequestHandler::process_onion_req(ProcessCiphertextError&& error,
        OnionRequestMetadata&& data) {

    switch (error) {
        case ProcessCiphertextError::INVALID_CIPHERTEXT:
            return data.cb({http::BAD_REQUEST, "Invalid ciphertext"});
        case ProcessCiphertextError::INVALID_JSON:
            return data.cb(wrap_proxy_response({http::BAD_REQUEST, "Invalid json"},
                    data.ephem_key, data.enc_type));
    }
}

void RequestHandler::process_onion_exit(
    std::string_view body,
    std::function<void(oxen::Response)> cb) {

    OXEN_LOG(debug, "Processing onion exit!");

    if (!service_node_.snode_ready())
        return cb({http::SERVICE_UNAVAILABLE, "Snode not ready"});

    this->process_client_req(body, std::move(cb));
}

void RequestHandler::process_proxy_exit(
        const x25519_pubkey& client_key,
        std::string_view payload,
        std::function<void(oxen::Response)> cb) {

    if (!service_node_.snode_ready())
        return cb(wrap_proxy_response(
                {http::SERVICE_UNAVAILABLE, "Snode not ready"},
                client_key, EncryptType::aes_cbc));

    static int proxy_idx = 0;

    int idx = proxy_idx++;

    OXEN_LOG(debug, "[{}] Process proxy exit", idx);

    std::string plaintext;

    try {
        plaintext = channel_cipher_.decrypt_cbc(payload, client_key);
    } catch (const std::exception& e) {
        auto msg = fmt::format("Invalid ciphertext: {}", e.what());
        OXEN_LOG(debug, "{}", msg);

        // TODO: since we always seem to encrypt the response, we should
        // do it once one level above instead
        return cb(wrap_proxy_response({http::BAD_REQUEST, std::move(msg)},
                    client_key, EncryptType::aes_cbc));
    }

    std::string body;

    try {
        const json req = json::parse(plaintext, nullptr, true);
        body = req.at("body").get<std::string>();
    } catch (const std::exception& e) {
        auto msg = fmt::format("JSON parsing error: {}", e.what());
        OXEN_LOG(debug, "[{}] {}", idx, msg);
        return cb(wrap_proxy_response(
                {http::BAD_REQUEST, std::move(msg)}, client_key, EncryptType::aes_cbc));
    }

    this->process_client_req(
        body, [this, cb = std::move(cb), client_key, idx](oxen::Response res) {
            OXEN_LOG(debug, "[{}] proxy about to respond with: {}", idx, res.status.first);

            cb(wrap_proxy_response(std::move(res), client_key, EncryptType::aes_cbc));
        });
}

void RequestHandler::process_onion_to_url(
    const std::string& protocol, const std::string& host, uint16_t port,
    const std::string& target, const std::string& payload,
    std::function<void(oxen::Response)> cb) {

    // TODO: investigate if the use of a shared pointer is necessary
    auto req = std::make_shared<request_t>();

    req->body() = payload;
    req->set(bhttp::field::host, host);
    req->method(bhttp::verb::post);
    req->target(target);

    req->prepare_payload();

    // `cb` needs to be adapted for http request
    auto http_cb = [cb = std::move(cb)](sn_response_t res) {
        if (res.error_code == SNodeError::NO_ERROR) {
            cb(oxen::Response{http::OK, *res.body});
        } else {
            OXEN_LOG(debug, "Oxen server error: {}", res.error_code);
            cb(oxen::Response{http::BAD_REQUEST, "Oxen Server error"});
        }
    };

    if (protocol != "https") {
        make_http_request(service_node_.ioc(), host, port, req, http_cb);
    } else {
        make_https_request(service_node_.ioc(), host, port, req, http_cb);
    }
}

} // namespace oxen
