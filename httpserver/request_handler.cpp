#include "loki_logger.h"
#include "request_handler.h"
#include "service_node.h"
#include "utils.hpp"
#include "channel_encryption.hpp"

using nlohmann::json;

namespace loki {

constexpr size_t MAX_MESSAGE_BODY = 102400; // 100 KB limit

std::string to_string(const Response& res) {

    std::stringstream ss;

    ss << "Status: " << static_cast<int>(res.status()) << ", ";
    ss << "ContentType: " << ((res.content_type() == ContentType::plaintext) ? "plaintext" : "json") << ", ";
    ss << "Body: <" << res.message() << ">";

    return ss.str();

}

RequestHandler::RequestHandler(ServiceNode& sn,
                               const ChannelEncryption<std::string>& ce)
    : service_node_(sn), channel_cipher_(ce) {}

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

    LOKI_LOG(trace, "Got client request to a wrong swarm");

    return Response{Status::MISDIRECTED_REQUEST, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_store(const json& params) {

    constexpr const char* fields[] = {"pubKey", "ttl", "nonce", "timestamp",
                                      "data"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {

            LOKI_LOG(debug, "Bad client request: no `{}` field", field);
            return Response{Status::BAD_REQUEST, fmt::format("invalid json: no `{}` field\n", field)};
        }
    }

    const auto ttl = params.at("ttl").get_ref<const std::string&>();
    const auto nonce = params.at("nonce").get_ref<const std::string&>();
    const auto timestamp = params.at("timestamp").get_ref<const std::string&>();
    const auto data = params.at("data").get_ref<const std::string&>();

    LOKI_LOG(trace, "Storing message: {}", data);

    bool created;
    auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), created);

    if (!created) {
        auto msg = fmt::format("Pubkey must be {} characters long\n",
                                  get_user_pubkey_size());
        LOKI_LOG(debug, "{}", msg);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        LOKI_LOG(debug, "Message body too long: {}", data.size());

        auto msg = fmt::format("Message body exceeds maximum allowed length of {}\n",
                        MAX_MESSAGE_BODY);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        LOKI_LOG(debug, "Forbidden. Invalid TTL: {}", ttl);
        return Response{Status::FORBIDDEN, "Provided TTL is not valid.\n"};
    }

    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        LOKI_LOG(debug, "Forbidden. Invalid Timestamp: {}", timestamp);
        return Response{Status::NOT_ACCEPTABLE, "Timestamp error: check your clock\n"};
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;

    const bool valid_pow =
        checkPoW(nonce, timestamp, ttl, pk.str(), data, messageHash,
                 service_node_.get_curr_pow_difficulty());
#ifndef DISABLE_POW
    if (!valid_pow) {
        LOKI_LOG(debug, "Forbidden. Invalid PoW nonce: {}", nonce);

        json res_body;
        res_body["difficulty"] = service_node_.get_curr_pow_difficulty();

        return Response{Status::INVALID_POW, res_body.dump(), ContentType::json};
    }
#endif

    bool success;

    try {
        const auto msg =
            message_t{pk.str(), data, messageHash, ttlInt, timestampInt, nonce};
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        LOKI_LOG(critical,
                 "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pk.str()));
        return Response{Status::INTERNAL_SERVER_ERROR, e.what()};
    }

    if (!success) {

        LOKI_LOG(warn, "Service node is initializing");
        return Response{Status::SERVICE_UNAVAILABLE, "Service node is initializing\n"};
    }

    LOKI_LOG(trace, "Successfully stored message for {}",
             obfuscate_pubkey(pk.str()));

    json res_body;
    res_body["difficulty"] = service_node_.get_curr_pow_difficulty();

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_retrieve_all() {

    std::vector<storage::Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res) {
        return Response{Status::INTERNAL_SERVER_ERROR, "could not retrieve all entries\n"};
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
        LOKI_LOG(debug, "Bad client request: no `pubKey` field");
        return Response{Status::BAD_REQUEST, "invalid json: no `pubKey` field\n"};
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params.at("pubKey").get<std::string>(), success);
    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        LOKI_LOG(debug, "{}", msg);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pk);

    LOKI_LOG(debug, "Snodes by pk size: {}", nodes.size());

    const json res_body = snodes_to_json(nodes);

    LOKI_LOG(debug, "Snodes by pk: {}", res_body.dump());

    return Response{Status::OK, res_body.dump(), ContentType::json};
}

Response RequestHandler::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            auto msg = fmt::format("invalid json: no `{}` field", field);
            LOKI_LOG(debug, "{}", msg);
            return Response{Status::BAD_REQUEST, std::move(msg)};
        }
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);

    if (!success) {

        auto msg = fmt::format("Pubkey must be {} characters long\n",
                               get_user_pubkey_size());
        LOKI_LOG(debug, "{}", msg);
        return Response{Status::BAD_REQUEST, std::move(msg)};
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        return this->handle_wrong_swarm(pk);
    }

    const std::string& last_hash = params.at("lastHash").get_ref<const std::string&>();

    // Note: We removed long-polling

    std::vector<storage::Item> items;

    if (!service_node_.retrieve(pk.str(), last_hash, items)) {

        auto msg = fmt::format(
            "Internal Server Error. Could not retrieve messages for {}",
            obfuscate_pubkey(pk.str()));
        LOKI_LOG(critical, "{}", msg);

        return Response{Status::INTERNAL_SERVER_ERROR, std::move(msg)};
    }

    if (!items.empty()) {
        LOKI_LOG(trace, "Successfully retrieved messages for {}",
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

Response RequestHandler::process_client_req(const std::string& req_json) {

    const json body = json::parse(req_json, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        LOKI_LOG(debug, "Bad client request: invalid json");
        return Response{Status::BAD_REQUEST, "invalid json\n"};
    }

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        LOKI_LOG(debug, "Bad client request: no method field");
        return Response{Status::BAD_REQUEST, "invalid json: no `method` field\n"};
    }

    const auto& method_name = method_it->get_ref<const std::string&>();

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        LOKI_LOG(debug, "Bad client request: no params field");
        return Response{Status::BAD_REQUEST, "invalid json: no `params` field\n"};
    }

    if (method_name == "store") {
        LOKI_LOG(debug, "Process client request: store");
        return this->process_store(*params_it);

    } else if (method_name == "retrieve") {
        LOKI_LOG(debug, "Process client request: retrieve");
        return this->process_retrieve(*params_it);
        // TODO: maybe we should check if (some old) clients requests long-polling and
        // then wait before responding to prevent spam

    } else if (method_name == "get_snodes_for_pubkey") {
        LOKI_LOG(debug, "Process client request: snodes for pubkey");
        return this->process_snodes_by_pk(*params_it);

    } else {
        LOKI_LOG(debug, "Bad client request: unknown method '{}'", method_name);
        return Response{Status::BAD_REQUEST, fmt::format("no method {}", method_name)};
    }
}

Response
RequestHandler::wrap_proxy_response(const Response& res,
                                    const std::string& client_key) const {

    nlohmann::json json_res;

    json_res["status"] = res.status();
    json_res["body"] = res.message();

    const std::string res_body = json_res.dump();
    /// change to encrypt_gcm
    std::string ciphertext = util::base64_encode(channel_cipher_.encrypt_gcm(res_body, client_key));

    // why does this have to be json???
    return Response{Status::OK, std::move(ciphertext), ContentType::json};
}

Response RequestHandler::process_onion_exit(const std::string& eph_key,
                                            const std::string& payload) {

    LOKI_LOG(debug, "Processing onion exit!");

    std::string body;

    try {
        const json req = json::parse(payload, nullptr, true);
        body = req.at("body").get<std::string>();

        // TODO: check if the client requested long-polling and see if we want
        // to do anything about it.
        LOKI_LOG(debug, "CLIENT HEADERS: \n\t{}", req.at("headers").dump(2));
    } catch (std::exception& e) {
        auto msg = fmt::format("JSON parsing error: {}", e.what());
        LOKI_LOG(error, "{}", msg);
        return {Status::BAD_REQUEST, msg};
    }

    const auto res = this->process_client_req(body);

    LOKI_LOG(debug, "about to respond with: {}", to_string(res));

    return wrap_proxy_response(res, eph_key);
}

Response RequestHandler::process_proxy_exit(const std::string& client_key,
                                            const std::string& payload) {

    LOKI_LOG(debug, "Process proxy exit");

    const auto plaintext = channel_cipher_.decrypt_cbc(payload, client_key);

    std::string body;

    try {
        const json req = json::parse(plaintext, nullptr, true);
        body = req.at("body").get<std::string>();

        // TOOD: check if the client requested long-polling and see if we want
        // to do anything about it.
        LOKI_LOG(debug, "CLIENT HEADERS: \n\t{}", req.at("headers").dump(2));
    } catch (std::exception& e) {
        auto msg = fmt::format("JSON parsing error: {}", e.what());
        LOKI_LOG(error, "{}", msg);

        return {Status::BAD_REQUEST, msg};
    }

    const auto res = this->process_client_req(body);

    LOKI_LOG(debug, "about to respond with: {}", to_string(res));

    return wrap_proxy_response(res, client_key);
}

void RequestHandler::process_onion_req(const std::string& ciphertext,
                                       const std::string& ephem_key,
                                       std::function<void(loki::Response)> cb) {

    std::string plaintext;

    static int counter = 0;

    try {
        const std::string ciphertext_bin = util::base64_decode(ciphertext);

        plaintext = channel_cipher_.decrypt_gcm(ciphertext_bin, ephem_key);
    } catch (const std::exception& e) {
        LOKI_LOG(debug, "Error decrypting an onion request: {}", e.what());
        // Should this error be propagated back to the client?
        cb(loki::Response{Status::BAD_REQUEST, "Invalid ciphertext"});
        return;
    }

    LOKI_LOG(debug, "onion request decrypted: <{}>", plaintext);

    try {

        const json inner_json = json::parse(plaintext, nullptr, true);

        if (inner_json.find("body") != inner_json.end()) {
            LOKI_LOG(debug, "We are the final destination in the onion request!");

            loki::Response res = this->process_onion_exit(ephem_key, plaintext);

            cb(std::move(res));
            return;
        } else if (inner_json.find("url") != inner_json.end()) {

            const auto& url = inner_json.at("url").get_ref<const std::string&>();
            LOKI_LOG(debug, "We are to forward the request to url: {}", url);


            // This will be an async request, so need to pass a callback (and make sure we don't respond until then)

            // TODO2: make open groups work!
            abort();

            // cb()
            return;
        }

        const auto& payload = inner_json.at("ciphertext").get_ref<const std::string&>();
        const auto& dest = inner_json.at("destination").get_ref<const std::string&>();
        const auto& ekey = inner_json.at("ephemeral_key").get_ref<const std::string&>();

        auto sn = service_node_.find_node_by_ed25519_pk(dest);

        if (!sn) {
            auto msg = fmt::format("Next node not found: {}", dest);
            LOKI_LOG(warn, "{}", msg);
            auto res = loki::Response{Status::BAD_REQUEST, std::move(msg)};
            cb(res);
            return;
        }

        nlohmann::json req_body;

        req_body["ciphertext"] = payload;
        req_body["ephemeral_key"] = ekey;

        auto on_response = [cb, counter_copy = counter](bool success, std::vector<std::string> data) {

            LOKI_LOG(debug, "on onion response, {}", counter_copy);
            LOKI_LOG(debug, "   success: {}", success);
            LOKI_LOG(debug, "   data.size: {}", data.size());

            for (const std::string& part : data) {
                LOKI_LOG(debug, "   part: {}", part);
            }

            if (!success) {
                LOKI_LOG(debug, "[Onion request] Request time out");
                cb(loki::Response{Status::BAD_REQUEST, "Request time out"});
                return;
            }

            // We only expect a two-part message
            if (data.size() != 2) {
                LOKI_LOG(debug, "[Onion request] Incorrect number of messages: {}", data.size());
                cb(loki::Response{Status::BAD_REQUEST, "Incorrect number of messages"});
                return;
            }

            /// We use http status codes (for now)
            if (data[0] == "200") {
                cb(loki::Response{Status::OK, std::move(data[1])});
            } else {
                LOKI_LOG(debug, "Onion request relay failed with: {}", data[1]);
                cb(loki::Response{Status::SERVICE_UNAVAILABLE, ""});
            }

        };

        LOKI_LOG(debug, "send_onion_to_sn, sn: {} reqidx: {}", *sn, counter++);

        // Note: we shouldn't use http here
        service_node_.send_onion_to_sn(*sn, payload, ekey, on_response);

    } catch (std::exception& e) {
        LOKI_LOG(debug, "Error parsing inner JSON in onion request: {}", e.what());
        cb(loki::Response{Status::BAD_REQUEST, "Invalid json"});
    }
}

} // namespace loki
