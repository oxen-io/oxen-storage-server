#include "request_handler.h"
#include "channel_encryption.hpp"
#include "http_connection.h"
#include "oxen_logger.h"
#include "service_node.h"
#include "utils.hpp"

#include "https_client.h"

#include <oxenmq/base64.h>
#include <nlohmann/json.hpp>

using nlohmann::json;

namespace oxen {

constexpr size_t MAX_MESSAGE_BODY = 102400; // 100 KB limit

std::string to_string(const Response& res) {

    std::stringstream ss;

    ss << "Status: " << static_cast<int>(res.status()) << ", ";
    ss << "ContentType: "
       << ((res.content_type() == ContentType::plaintext) ? "plaintext"
                                                          : "json")
       << ", ";
    ss << "Body: <" << res.message() << ">";

    return ss.str();
}

RequestHandler::RequestHandler(boost::asio::io_context& ioc, ServiceNode& sn,
                               const OxendClient& oxend_client,
                               const ChannelEncryption<std::string>& ce)
    : ioc_(ioc), service_node_(sn), oxend_client_(oxend_client),
      channel_cipher_(ce) {}

static json snodes_to_json(const std::vector<sn_record_t>& snodes) {

    json res_body;
    json snodes_json = json::array();

    for (const auto& sn : snodes) {
        json snode;
        snode["address"] = sn.sn_address();
        snode["pubkey_x25519"] = sn.pubkey_x25519_hex();
        snode["pubkey_ed25519"] = sn.pubkey_ed25519_hex();
        snode["port"] = std::to_string(sn.port());
        snode["ip"] = sn.ip();
        snodes_json.push_back(snode);
    }

    res_body["snodes"] = snodes_json;

    return res_body;
}

static std::string obfuscate_pubkey(const std::string& pk) {
    std::string res = pk.substr(0, 2);
    res += "...";
    res += pk.substr(pk.length() - 3, pk.length() - 1);
    return res;
}

/// TODO: this probably shouldn't return Response...
Response RequestHandler::handle_wrong_swarm(const user_pubkey_t& pubKey) {

    const std::vector<sn_record_t> nodes =
        service_node_.get_snodes_by_pk(pubKey);
    const json res_body = snodes_to_json(nodes);

    OXEN_LOG(trace, "Got client request to a wrong swarm");

    return Response{Status::MISDIRECTED_REQUEST, res_body.dump(),
                    ContentType::json};
}

Response RequestHandler::process_store(const json& params) {

    constexpr const char* fields[] = {"pubKey", "ttl", "nonce", "timestamp",
                                      "data"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {

            OXEN_LOG(debug, "Bad client request: no `{}` field", field);
            return Response{
                Status::BAD_REQUEST,
                fmt::format("invalid json: no `{}` field\n", field)};
        }
    }

    const auto& ttl = params.at("ttl").get_ref<const std::string&>();
    const auto& nonce = params.at("nonce").get_ref<const std::string&>();
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
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        OXEN_LOG(debug, "Message body too long: {}", data.size());

        auto msg =
            fmt::format("Message body exceeds maximum allowed length of {}\n",
                        MAX_MESSAGE_BODY);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        OXEN_LOG(debug, "Forbidden. Invalid TTL: {}", ttl);
        return Response{Status::FORBIDDEN, "Provided TTL is not valid.\n"};
    }

    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        OXEN_LOG(debug, "Forbidden. Invalid Timestamp: {}", timestamp);
        return Response{Status::NOT_ACCEPTABLE,
                        "Timestamp error: check your clock\n"};
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;

    const bool valid_pow =
        checkPoW(nonce, timestamp, ttl, pk.str(), data, messageHash,
                 service_node_.get_curr_pow_difficulty());
#ifndef DISABLE_POW
    if (!valid_pow) {
        OXEN_LOG(debug, "Forbidden. Invalid PoW nonce: {}", nonce);

        json res_body;
        res_body["difficulty"] = service_node_.get_curr_pow_difficulty();

        return Response{Status::INVALID_POW, res_body.dump(),
                        ContentType::json};
    }
#endif

    bool success;

    try {
        const auto msg =
            message_t{pk.str(), data, messageHash, ttlInt, timestampInt, nonce};
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        OXEN_LOG(critical,
                 "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pk.str()));
        return Response{Status::INTERNAL_SERVER_ERROR, e.what()};
    }

    if (!success) {

        OXEN_LOG(warn, "Service node is initializing");
        return Response{Status::SERVICE_UNAVAILABLE,
                        "Service node is initializing\n"};
    }

    OXEN_LOG(trace, "Successfully stored message for {}",
             obfuscate_pubkey(pk.str()));

    json res_body;
    res_body["difficulty"] = service_node_.get_curr_pow_difficulty();

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_retrieve_all() {

    std::vector<storage::Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res) {
        return Response{Status::INTERNAL_SERVER_ERROR,
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

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_snodes_by_pk(const json& params) const {

    if (!params.contains("pubKey")) {
        OXEN_LOG(debug, "Bad client request: no `pubKey` field");
        return Response{Status::BAD_REQUEST,
                        "invalid json: no `pubKey` field\n"};
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), success);
    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        OXEN_LOG(debug, "{}", msg);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pk);

    OXEN_LOG(debug, "Snodes by pk size: {}", nodes.size());

    const json res_body = snodes_to_json(nodes);

    OXEN_LOG(debug, "Snodes by pk: {}", res_body.dump());

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            auto msg = fmt::format("invalid json: no `{}` field", field);
            OXEN_LOG(debug, "{}", msg);
            return Response{Status::BAD_REQUEST, std::move(msg)};
        }
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);

    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        OXEN_LOG(debug, "{}", msg);
        return Response{Status::BAD_REQUEST, std::move(msg)};
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

        return Response{Status::INTERNAL_SERVER_ERROR, std::move(msg)};
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

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

void RequestHandler::process_client_req(
    const std::string& req_json, std::function<void(oxen::Response)> cb) {

    OXEN_LOG(trace, "process_client_req str <{}>", req_json);

    const json body = json::parse(req_json, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        OXEN_LOG(debug, "Bad client request: invalid json");
        cb(Response{Status::BAD_REQUEST, "invalid json\n"});
    }

    OXEN_LOG(trace, "process_client_req json <{}>", body.dump(2));

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        OXEN_LOG(debug, "Bad client request: no method field");
        cb(Response{Status::BAD_REQUEST, "invalid json: no `method` field\n"});
    }

    const auto& method_name = method_it->get_ref<const std::string&>();

    OXEN_LOG(trace, "  - method name: {}", method_name);

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        OXEN_LOG(debug, "Bad client request: no params field");
        cb(Response{Status::BAD_REQUEST, "invalid json: no `params` field\n"});
    }

    if (method_name == "store") {
        OXEN_LOG(debug, "Process client request: store");
        cb(this->process_store(*params_it));

    } else if (method_name == "retrieve") {
        OXEN_LOG(debug, "Process client request: retrieve");
        cb(this->process_retrieve(*params_it));
        // TODO: maybe we should check if (some old) clients requests
        // long-polling and then wait before responding to prevent spam

    } else if (method_name == "get_snodes_for_pubkey") {
        OXEN_LOG(debug, "Process client request: snodes for pubkey");
        cb(this->process_snodes_by_pk(*params_it));
    } else if (method_name == "get_lns_mapping") {

        const auto name_it = params_it->find("name_hash");
        if (name_it == params_it->end()) {
            cb(Response{Status::BAD_REQUEST, "Field <name_hash> is missing"});
        } else {
            this->process_lns_request(*name_it, std::move(cb));
        }

    } else {
        OXEN_LOG(debug, "Bad client request: unknown method '{}'", method_name);
        cb(Response{Status::BAD_REQUEST,
                    fmt::format("no method {}", method_name)});
    }
}

Response RequestHandler::wrap_proxy_response(const Response& res,
                                             const std::string& client_key,
                                             bool use_gcm) const {

    nlohmann::json json_res;

    json_res["status"] = res.status();
    json_res["body"] = res.message();

    const std::string res_body = json_res.dump();

    std::string ciphertext;

    if (use_gcm) {
        ciphertext = oxenmq::to_base64(
            channel_cipher_.encrypt_gcm(res_body, client_key));
    } else {
        ciphertext = oxenmq::to_base64(
            channel_cipher_.encrypt_cbc(res_body, client_key));
    }

    // why does this have to be json???
    return Response{Status::OK, std::move(ciphertext), ContentType::json};
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

    // this should not be called "sn response"
    auto on_oxend_res = [cb = std::move(cb)](sn_response_t sn) {
        if (sn.error_code == SNodeError::NO_ERROR && sn.body) {
            cb({Status::OK, *sn.body});
        } else {
            cb({Status::BAD_REQUEST, "unknown oxend error"});
        }
    };

#ifdef INTEGRATION_TEST
    // use mainnet seed
    oxend_client_.make_custom_oxend_request("public.loki.foundation", 22023,
                                            "lns_names_to_owners", params,
                                            std::move(on_oxend_res));
#else
    oxend_client_.make_oxend_request("lns_names_to_owners", params,
                                     std::move(on_oxend_res));
#endif
}

void RequestHandler::process_onion_exit(
    const std::string& eph_key, const std::string& body,
    std::function<void(oxen::Response)> cb) {

    OXEN_LOG(debug, "Processing onion exit!");

    if (!service_node_.snode_ready()) {
        cb({Status::SERVICE_UNAVAILABLE, "Snode not ready"});
        return;
    }

    this->process_client_req(body, std::move(cb));
}

void RequestHandler::process_proxy_exit(
    const std::string& client_key, const std::string& payload,
    std::function<void(oxen::Response)> cb) {

    if (!service_node_.snode_ready()) {
        auto res = Response{Status::SERVICE_UNAVAILABLE, "Snode not ready"};
        cb(wrap_proxy_response(res, client_key, false));
        return;
    }

    static int proxy_idx = 0;

    int idx = proxy_idx++;

    OXEN_LOG(debug, "[{}] Process proxy exit", idx);

    std::string plaintext;

    try {
        plaintext = channel_cipher_.decrypt_cbc(payload, client_key);
    } catch (const std::exception& e) {
        auto msg = fmt::format("Invalid ciphertext: {}", e.what());
        OXEN_LOG(debug, "{}", msg);
        auto res = Response{Status::BAD_REQUEST, std::move(msg)};

        // TODO: since we always seem to encrypt the response, we should
        // do it once one level above instead
        cb(wrap_proxy_response(res, client_key, false));
        return;
    }

    std::string body;

    bool lp_used = false;

    try {
        const json req = json::parse(plaintext, nullptr, true);
        body = req.at("body").get<std::string>();

        if (req.find("headers") != req.end()) {
            if (req.at("headers").find(OXEN_LONG_POLL_HEADER) !=
                req.at("headers").end()) {
                lp_used =
                    req.at("headers").at(OXEN_LONG_POLL_HEADER).get<bool>();
            }
        }

    } catch (std::exception& e) {
        auto msg = fmt::format("JSON parsing error: {}", e.what());
        OXEN_LOG(debug, "[{}] {}", idx, msg);
        auto res = Response{Status::BAD_REQUEST, msg};
        cb(wrap_proxy_response(res, client_key, false /* use cbc */));
        return;
    }

    if (lp_used) {
        OXEN_LOG(debug, "Long polling requested over a proxy request");
    }

    this->process_client_req(
        body, [this, cb = std::move(cb), client_key, idx](oxen::Response res) {
            OXEN_LOG(debug, "[{}] proxy about to respond with: {}", idx,
                     res.status());

            cb(wrap_proxy_response(res, client_key, false /* use cbc */));
        });
}

void RequestHandler::process_onion_to_url(
    const std::string& host, const std::string& target,
    const std::string& payload, std::function<void(oxen::Response)> cb) {

    // TODO: investigate if the use of a shared pointer is necessary
    auto req = std::make_shared<request_t>();

    req->body() = payload;
    req->set(http::field::host, host);
    req->method(http::verb::post);
    req->target(target);

    req->prepare_payload();

    // `cb` needs to be adapted for http request
    auto http_cb = [cb = std::move(cb)](sn_response_t res) {
        if (res.error_code == SNodeError::NO_ERROR) {
            cb(oxen::Response{Status::OK, *res.body});
        } else {
            OXEN_LOG(debug, "Oxen server error: {}", res.error_code);
            cb(oxen::Response{Status::BAD_REQUEST, "Oxen Server error"});
        }
    };

    make_https_request(ioc_, host, req, http_cb);
}

} // namespace oxen
