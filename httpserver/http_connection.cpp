#include "http_connection.h"
#include "Database.hpp"
#include "Item.hpp"
#include "channel_encryption.hpp"
#include "pow.hpp"
#include "rate_limiter.h"
#include "serialization.h"
#include "service_node.h"
#include "signature.h"
#include "utils.hpp"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <thread>

#include <boost/beast/core/detail/base64.hpp>
#include <boost/log/trivial.hpp>

using json = nlohmann::json;

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>
using namespace service_node;

/// +===========================================

static constexpr auto LOKI_EPHEMKEY_HEADER = "X-Loki-EphemKey";

using service_node::storage::Item;

using error_code = boost::system::error_code;

namespace loki {

constexpr auto SESSION_TIME_LIMIT = std::chrono::seconds(30);
constexpr auto TEST_RETRY_PERIOD = std::chrono::milliseconds(50);

// Note: on the client side the limit is different
// as it is not encrypted/encoded there yet.
// The choice is somewhat arbitrary but it roughly
// corresponds to the client-side limit of 2000 chars
// of unencrypted message body in our experiments
// (rounded up)
constexpr size_t MAX_MESSAGE_BODY = 3100;

static void log_error(const error_code& ec) {
    BOOST_LOG_TRIVIAL(error)
        << boost::format("Error(%1%): %2%\n") % ec.value() % ec.message();
}

void make_http_request(boost::asio::io_context& ioc,
                       const std::string& sn_address, uint16_t port,
                       const std::shared_ptr<request_t>& req,
                       http_callback_t&& cb) {

    error_code ec;
    tcp::endpoint endpoint;
    tcp::resolver resolver(ioc);
#ifdef INTEGRATION_TEST
    tcp::resolver::iterator destination =
        resolver.resolve("0.0.0.0", "http", ec);
#else
    tcp::resolver::iterator destination =
        resolver.resolve(sn_address, "http", ec);
#endif
    if (ec) {
        BOOST_LOG_TRIVIAL(error)
            << "Failed to parse the IP address. Error code = " << ec.value()
            << ". Message: " << ec.message();
        return;
    }
    while (destination != tcp::resolver::iterator()) {
        endpoint = *destination++;
    }
    endpoint.port(port);

    auto session =
        std::make_shared<HttpClientSession>(ioc, endpoint, req, std::move(cb));

    session->start();
}

static void
parse_swarm_update(const std::shared_ptr<std::string>& response_body,
                   const swarm_callback_t&& cb) {
    const json body = json::parse(*response_body, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        BOOST_LOG_TRIVIAL(error) << "Bad lokid rpc response: invalid json";
        return;
    }
    std::map<swarm_id_t, std::vector<sn_record_t>> swarm_map;
    block_update_t bu;

    try {
        const json service_node_states =
            body.at("result").at("service_node_states");

        for (const auto& sn_json : service_node_states) {
            const std::string pubkey =
                sn_json.at("service_node_pubkey").get<std::string>();

            const swarm_id_t swarm_id =
                sn_json.at("swarm_id").get<swarm_id_t>();
            std::string snode_address = util::hex64_to_base32z(pubkey);
            snode_address.append(".snode");
            const uint16_t port = sn_json.at("storage_port").get<uint16_t>();
            const std::string snode_ip =
                sn_json.at("public_ip").get<std::string>();
            const sn_record_t sn{port, snode_address, snode_ip};

            swarm_map[swarm_id].push_back(sn);
        }

        bu.height = body.at("result").at("height").get<uint64_t>();
        bu.block_hash = body.at("result").at("block_hash").get<std::string>();

    } catch (...) {
        BOOST_LOG_TRIVIAL(error) << "Bad lokid rpc response: invalid json";
        return;
    }

    for (auto const& swarm : swarm_map) {
        bu.swarms.emplace_back(SwarmInfo{swarm.first, swarm.second});
    }

    try {
        cb(bu);
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error)
            << "Exception caught on swarm update: " << e.what();
    }
}

void request_swarm_update(boost::asio::io_context& ioc,
                          const swarm_callback_t&& cb,
                          uint16_t lokid_rpc_port) {
    BOOST_LOG_TRIVIAL(trace) << "UPDATING SWARMS: begin";

    const std::string ip = "127.0.0.1";
    const std::string target = "/json_rpc";
    const std::string req_body =
        R"#({
            "jsonrpc":"2.0",
            "id":"0",
            "method":"get_service_nodes",
            "params": {
                "sevice_node_pubkeys": []
            }
        })#";

    auto req = std::make_shared<request_t>();

    req->body() = req_body;
    req->method(http::verb::post);
    req->target(target);
    req->prepare_payload();

    make_http_request(ioc, ip, lokid_rpc_port, req,
                      [cb = std::move(cb)](const sn_response_t&& res) {
                          if (res.body) {
                              parse_swarm_update(res.body, std::move(cb));
                          } else {
                              BOOST_LOG_TRIVIAL(error)
                                  << "ERROR: Didn't get swarm request body";
                          }
                      });
}

namespace http_server {

// "Loop" forever accepting new connections.
static void
accept_connection(boost::asio::io_context& ioc, tcp::acceptor& acceptor,
                  ServiceNode& sn,
                  ChannelEncryption<std::string>& channel_encryption,
                  RateLimiter& rate_limiter) {

    acceptor.async_accept([&](const error_code& ec, tcp::socket socket) {
        BOOST_LOG_TRIVIAL(trace) << "connection accepted";
        if (!ec)
            std::make_shared<connection_t>(ioc, std::move(socket), sn,
                                           channel_encryption, rate_limiter)
                ->start();

        if (ec)
            log_error(ec);

        accept_connection(ioc, acceptor, sn, channel_encryption, rate_limiter);
    });
}

void run(boost::asio::io_context& ioc, std::string& ip, uint16_t port,
         ServiceNode& sn, ChannelEncryption<std::string>& channel_encryption,
         RateLimiter& rate_limiter) {

    BOOST_LOG_TRIVIAL(trace) << "http server run";

    const auto address =
        boost::asio::ip::make_address(ip); /// throws if incorrect

    tcp::acceptor acceptor{ioc, {address, port}};

    accept_connection(ioc, acceptor, sn, channel_encryption, rate_limiter);

    ioc.run();
}

/// ============ connection_t ============

connection_t::connection_t(boost::asio::io_context& ioc, tcp::socket socket,
                           ServiceNode& sn,
                           ChannelEncryption<std::string>& channel_encryption,
                           RateLimiter& rate_limiter)
    : ioc_(ioc), socket_(std::move(socket)), service_node_(sn),
      channel_cipher_(channel_encryption), repeat_timer_(ioc),
      deadline_(ioc, SESSION_TIME_LIMIT),
      notification_ctx_({boost::asio::steady_timer{ioc}, boost::none}),
      rate_limiter_(rate_limiter) {

    BOOST_LOG_TRIVIAL(trace) << "connection_t";
}

connection_t::~connection_t() { BOOST_LOG_TRIVIAL(trace) << "~connection_t"; }

void connection_t::start() {
    register_deadline();
    read_request();
}

void connection_t::notify(const message_t& msg) {
    BOOST_LOG_TRIVIAL(debug) << "Processing message notification: " << msg.data;
    // save messages, so we can access them once the timer event happens
    notification_ctx_.message = msg;
    // the timer callback will be called once we complete the current callback
    notification_ctx_.timer.cancel();
}

void connection_t::reset() {
    BOOST_LOG_TRIVIAL(debug) << "Resetting the connection";
    notification_ctx_.timer.cancel();
}

// Asynchronously receive a complete request message.
void connection_t::read_request() {

    auto self = shared_from_this();

    auto on_data = [self](error_code ec, size_t bytes_transferred) {
        BOOST_LOG_TRIVIAL(trace)
            << "on data: " << bytes_transferred << " bytes";

        if (ec) {
            log_error(ec);
            return;
        }

        // NOTE: this is blocking, we should make this asynchronous
        try {
            self->process_request();
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "Exception caught: " << e.what();
            self->body_stream_ << e.what();
        }

        if (!self->delay_response_) {
            self->write_response();
        }
    };

    http::async_read(socket_, buffer_, request_, on_data);
}

bool connection_t::validate_snode_request() {
    if (!parse_header(LOKI_SENDER_SNODE_PUBKEY_HEADER,
                      LOKI_SNODE_SIGNATURE_HEADER)) {
        BOOST_LOG_TRIVIAL(error) << "Missing signature headers";
        return false;
    }
    const auto& signature = header_[LOKI_SNODE_SIGNATURE_HEADER];
    const auto& public_key_b32z = header_[LOKI_SENDER_SNODE_PUBKEY_HEADER];

    /// Known service node
    const std::string snode_address = public_key_b32z + ".snode";
    if (!service_node_.is_snode_address_known(snode_address)) {
        body_stream_ << "Unknown service node\n";
        BOOST_LOG_TRIVIAL(error)
            << "Discarding signature from unknown service node "
            << public_key_b32z;
        response_.result(http::status::unauthorized);
        return false;
    }

    if (!verify_signature(signature, public_key_b32z)) {
        constexpr auto msg = "Could not verify batch signature";
        BOOST_LOG_TRIVIAL(warning) << msg;
        body_stream_ << msg;
        response_.result(http::status::unauthorized);
        return false;
    }
    if (rate_limiter_.should_rate_limit(public_key_b32z)) {
        response_.result(http::status::too_many_requests);
        return false;
    }
    return true;
}

bool connection_t::verify_signature(const std::string& signature,
                                    const std::string& public_key_b32z) {
    const auto body_hash = hash_data(request_.body());
    return check_signature(signature, body_hash, public_key_b32z);
}

void connection_t::process_message_test_req(uint64_t height,
                                            const std::string& tester_addr,
                                            const std::string& msg_hash) {

    BOOST_LOG_TRIVIAL(debug)
        << "Performing message test, attempt: " << repetition_count_;

    std::string answer;

    const MessageTestStatus status = service_node_.process_msg_test_req(
        height, tester_addr, msg_hash, answer);
    if (status == MessageTestStatus::SUCCESS) {
        delay_response_ = true;
        body_stream_ << answer;
        response_.result(http::status::ok);
        this->write_response();
    } else if (status == MessageTestStatus::RETRY) {
        delay_response_ = true;
        repetition_count_++;

        repeat_timer_.expires_after(TEST_RETRY_PERIOD);
        repeat_timer_.async_wait([self = shared_from_this(), height, msg_hash,
                                  tester_addr](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    log_error(ec);
                }
            } else {
                self->process_message_test_req(height, tester_addr, msg_hash);
            }
        });

    } else {
        response_.result(http::status::bad_request);
        /// TODO: send a helpful error message
    }
}

// Determine what needs to be done with the request message.
void connection_t::process_request() {

    /// This method is responsible for filling out response_

    BOOST_LOG_TRIVIAL(trace) << "process request";
    response_.version(request_.version());
    response_.keep_alive(false);

    /// TODO: make sure that we always send a response!

    response_.result(http::status::bad_request);

    const auto target = request_.target();
    switch (request_.method()) {
    case http::verb::post:
        if (target == "/v1/storage_rpc") {
            /// Store/load from clients
            BOOST_LOG_TRIVIAL(trace) << "got /v1/storage_rpc";

            try {
                process_client_req();
            } catch (std::exception& e) {
                response_.result(http::status::internal_server_error);
                BOOST_LOG_TRIVIAL(error)
                    << "exception caught while processing client request: "
                    << e.what();
            }

            /// Make sure only service nodes can use this API
        } else if (target == "/v1/swarms/push") {

            BOOST_LOG_TRIVIAL(trace) << "swarms/push";

#ifndef DISABLE_SNODE_SIGNATURE
            if (!validate_snode_request()) {
                return;
            }
#endif

            /// NOTE:: we only expect one message here, but
            /// for now lets reuse the function we already have
            std::vector<message_t> messages =
                deserialize_messages(request_.body());
            assert(messages.size() == 1);

            service_node_.process_push(messages.front());

            response_.result(http::status::ok);
        } else if (target == "/v1/swarms/push_batch") {
#ifndef DISABLE_SNODE_SIGNATURE
            if (!validate_snode_request()) {
                return;
            }
#endif
            response_.result(http::status::ok);
            service_node_.process_push_batch(request_.body());

        } else if (target == "/msg_test") {
            BOOST_LOG_TRIVIAL(debug) << "Got message test request";

#ifndef DISABLE_SNODE_SIGNATURE
            if (!validate_snode_request()) {
                return;
            }
#endif

            using nlohmann::json;

            const json body = json::parse(request_.body(), nullptr, false);

            if (body == nlohmann::detail::value_t::discarded) {
                BOOST_LOG_TRIVIAL(error)
                    << "Bad snode test request: invalid json";
                response_.result(http::status::bad_request);
                return;
            }

            uint64_t blk_height;
            std::string msg_hash;

            try {
                blk_height = body.at("height").get<uint64_t>();
                msg_hash = body.at("hash").get<std::string>();
            } catch (...) {
                response_.result(http::status::bad_request);
                BOOST_LOG_TRIVIAL(error)
                    << "Bad snode test request: missing fields in json";
                return;
            }

            std::string tester_pk;
#ifndef DISABLE_SNODE_SIGNATURE
            // Note we know that the header is present because we already
            // verified the signature (how can we enforce that in code?)
            tester_pk = header_.at(LOKI_SENDER_SNODE_PUBKEY_HEADER);
            tester_pk.append(".snode");
#endif

            this->process_message_test_req(blk_height, tester_pk, msg_hash);
        }
#ifdef INTEGRATION_TEST
        else if (target == "/retrieve_all") {
            process_retrieve_all();
        } else if (target == "/quit") {
            BOOST_LOG_TRIVIAL(info) << "got /quit request";
            // a bit of a hack: sending response manually
            delay_response_ = true;
            response_.result(http::status::ok);
            write_response();
            ioc_.stop();
        }
#endif
        else {
            BOOST_LOG_TRIVIAL(error) << "unknown target: " << target;
            response_.result(http::status::not_found);
        }
        break;
    case http::verb::get:
        BOOST_LOG_TRIVIAL(error) << "GET requests not supported";
        response_.result(http::status::bad_request);
        break;
    default:
        BOOST_LOG_TRIVIAL(error) << "bad request";
        response_.result(http::status::bad_request);
        break;
    }
}

static std::string obfuscate_pubkey(const std::string& pk) {
    std::string res = pk.substr(0, 2);
    res += "...";
    res += pk.substr(pk.length() - 3, pk.length() - 1);
    return res;
}

// Asynchronously transmit the response message.
void connection_t::write_response() {

#ifndef DISABLE_ENCRYPTION
    const auto it = header_.find(LOKI_EPHEMKEY_HEADER);
    if (it != header_.end()) {
        const std::string& ephemKey = it->second;
        try {
            auto body = channel_cipher_.encrypt(body_stream_.str(), ephemKey);
            response_.body() = boost::beast::detail::base64_encode(body);
            response_.set(http::field::content_type, "text/plain");
        } catch (const std::exception& e) {
            response_.result(http::status::internal_server_error);
            response_.set(http::field::content_type, "text/plain");
            body_stream_ << "Could not encrypt/encode response: ";
            body_stream_ << e.what() << "\n";
            response_.body() = body_stream_.str();
            BOOST_LOG_TRIVIAL(error)
                << "Internal Server Error. Could not encrypt response for "
                << obfuscate_pubkey(ephemKey);
        }
    }
#else
    response_.body() = body_stream_.str();
#endif

    response_.set(http::field::content_length, response_.body().size());

    auto self = shared_from_this();

    /// This attempts to write all data to a stream
    /// TODO: handle the case when we are trying to send too much
    http::async_write(socket_, response_, [self](error_code ec, size_t) {
        self->socket_.shutdown(tcp::socket::shutdown_send, ec);
        self->deadline_.cancel();
    });
}

bool connection_t::parse_header(const char* key) {
    const auto it = request_.find(key);
    if (it == request_.end()) {
        body_stream_ << "Missing field in header : " << key << "\n";
        return false;
    }
    header_[key] = it->value().to_string();
    return true;
}

template <typename... Args>
bool connection_t::parse_header(const char* first, Args... args) {
    return parse_header(first) && parse_header(args...);
}

json snodes_to_json(const std::vector<sn_record_t>& snodes) {

    json res_body;
    json snodes_json = json::array();

    for (const auto& sn : snodes) {
        json snode;
        snode["address"] = sn.address;
        snode["port"] = std::to_string(sn.port);
        snode["ip"] = sn.ip;
        snodes_json.push_back(snode);
    }

    res_body["snodes"] = snodes_json;

    return res_body;
}

void connection_t::process_store(const json& params) {

    constexpr const char* fields[] = {"pubKey", "ttl", "nonce", "timestamp",
                                      "data"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            body_stream_ << boost::format("invalid json: no `%1%` field\n") %
                                field;
            BOOST_LOG_TRIVIAL(error)
                << boost::format("Bad client request: no `%1%` field") % field;
            return;
        }
    }

    const auto pubKey = params["pubKey"].get<std::string>();
    const auto ttl = params["ttl"].get<std::string>();
    const auto nonce = params["nonce"].get<std::string>();
    const auto timestamp = params["timestamp"].get<std::string>();
    const auto data = params["data"].get<std::string>();

    if (pubKey.size() != 66) {
        response_.result(http::status::bad_request);
        body_stream_ << "Pubkey must be 66 characters long\n";
        BOOST_LOG_TRIVIAL(error) << "Pubkey must be 66 characters long ";
        return;
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        response_.result(http::status::bad_request);
        body_stream_ << "Message body exceeds maximum allowed length of "
                     << MAX_MESSAGE_BODY << "\n";
        BOOST_LOG_TRIVIAL(error) << "Message body too long: " << data.size();
        return;
    }

    if (!service_node_.is_pubkey_for_us(pubKey)) {
        handle_wrong_swarm(pubKey);
        return;
    }

#ifdef INTEGRATION_TEST
    BOOST_LOG_TRIVIAL(trace) << "store body: " << data;
#endif

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        response_.result(http::status::forbidden);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Provided TTL is not valid.\n";
        BOOST_LOG_TRIVIAL(error) << "Forbidden. Invalid TTL " << ttl;
        return;
    }
    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        response_.result(http::status::not_acceptable);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Timestamp error: check your clock\n";
        BOOST_LOG_TRIVIAL(error)
            << "Forbidden. Invalid Timestamp " << timestamp;
        return;
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;

    const bool validPoW =
        checkPoW(nonce, timestamp, ttl, pubKey, data, messageHash,
                 service_node_.get_pow_difficulty());
#ifndef DISABLE_POW
    if (!validPoW) {
        response_.result(http::status::payment_required);
        response_.set(http::field::content_type, "text/plain");

        json res_body;
        res_body["difficulty"] = service_node_.get_pow_difficulty();
        BOOST_LOG_TRIVIAL(error) << "Forbidden. Invalid PoW nonce " << nonce;

        /// This might throw if not utf-8 endoded
        body_stream_ << res_body.dump();
        return;
    }
#endif

    bool success;

    try {
        const auto msg =
            message_t{pubKey, data, messageHash, ttlInt, timestampInt, nonce};
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << e.what() << "\n";
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not store message for "
            << obfuscate_pubkey(pubKey);
        return;
    }

    if (!success) {
        response_.result(http::status::service_unavailable);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Service node is initializing\n";
        BOOST_LOG_TRIVIAL(warning) << "Service node is initializing";
        return;
    }

    response_.result(http::status::ok);
    BOOST_LOG_TRIVIAL(trace)
        << "Successfully stored message for " << obfuscate_pubkey(pubKey);
}

void connection_t::process_snodes_by_pk(const json& params) {

    if (!params.contains("pubKey")) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `pubKey` field\n";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: no `pubKey` field";
        return;
    }

    auto pubKey = params["pubKey"].get<std::string>();

    if (pubKey.size() != 66) {
        response_.result(http::status::bad_request);
        body_stream_ << "Pubkey must be 66 characters long\n";
        BOOST_LOG_TRIVIAL(error) << "Pubkey must be 66 characters long ";
        return;
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pubKey);
    const json res_body = snodes_to_json(nodes);

    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    body_stream_ << res_body.dump();
}

void connection_t::process_retrieve_all() {

    std::vector<Item> all_entries;

    bool res = service_node_.get_all_messages(all_entries);

    if (!res) {
        response_.result(http::status::internal_server_error);
        return;
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

    body_stream_ << res_body.dump();
    response_.result(http::status::ok);
}

void connection_t::handle_wrong_swarm(const std::string& pubKey) {

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pubKey);
    const json res_body = snodes_to_json(nodes);

    response_.result(http::status::misdirected_request);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    body_stream_ << res_body.dump();
    BOOST_LOG_TRIVIAL(info) << "Client request for different swarm received";
}

constexpr auto LONG_POLL_TIMEOUT = std::chrono::milliseconds(20000);

template <typename T>
void connection_t::respond_with_messages(const std::vector<T>& items) {

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

    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");
    body_stream_ << res_body.dump();

    this->write_response();
}

void connection_t::poll_db(const std::string& pk,
                           const std::string& last_hash) {

    std::vector<Item> items;

    if (!service_node_.retrieve(pk, last_hash, items)) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not retrieve messages for "
            << obfuscate_pubkey(pk);
        return;
    }

    const bool lp_requested =
        request_.find("X-Loki-Long-Poll") != request_.end();

    if (!items.empty()) {
        BOOST_LOG_TRIVIAL(trace)
            << "Successfully retrieved messages for " << obfuscate_pubkey(pk);
    }

    if (items.empty() && lp_requested) {

        auto self = shared_from_this();

        // Instead of responding immediately, we delay the response
        // until new data arrives for this PubKey
        service_node_.register_listener(pk, self);

        notification_ctx_.timer.expires_after(LONG_POLL_TIMEOUT);
        notification_ctx_.timer.async_wait([=](const error_code& ec) {
            // we use timer cancellation as notification mechanism
            if (ec == boost::asio::error::operation_aborted) {

                std::vector<message_t> items;
                auto msg = notification_ctx_.message;
                if (msg) {
                    items.push_back(*msg);
                }

                respond_with_messages(items);
            } else {
                // If we are here, the notification timer expired
                // with no messages ready
                respond_with_messages<Item>({});
            }
        });

        BOOST_LOG_TRIVIAL(error) << "just registered notification";

    } else {

        respond_with_messages(items);
    }
}

void connection_t::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            body_stream_ << boost::format("invalid json: no `%1%` field\n") %
                                field;
            BOOST_LOG_TRIVIAL(error)
                << boost::format("Bad client request: no `%1%` field") % field;
            return;
        }
    }

    const auto pub_key = params["pubKey"].get<std::string>();
    const auto last_hash = params["lastHash"].get<std::string>();

    if (!service_node_.is_pubkey_for_us(pub_key)) {
        handle_wrong_swarm(pub_key);
        return;
    }

    // we are going send the response anynchronously
    // once we have new data
    delay_response_ = true;

    poll_db(pub_key, last_hash);
}

void connection_t::process_client_req() {
    std::string plain_text = request_.body();

#ifndef DISABLE_ENCRYPTION
    if (!parse_header(LOKI_EPHEMKEY_HEADER)) {
        BOOST_LOG_TRIVIAL(error) << "Could not parse headers\n";
        return;
    }

    try {
        const std::string decoded =
            boost::beast::detail::base64_decode(plain_text);
        plain_text =
            channel_cipher_.decrypt(decoded, header_[LOKI_EPHEMKEY_HEADER]);
    } catch (const std::exception& e) {
        response_.result(http::status::bad_request);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Could not decode/decrypt body: ";
        body_stream_ << e.what() << "\n";
        BOOST_LOG_TRIVIAL(error) << "Bad Request. Could not decrypt body";
        return;
    }
#endif

    const json body = json::parse(plain_text, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json\n";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: invalid json";
        return;
    }

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `method` field\n";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: no method field";
        return;
    }

    const auto method_name = method_it->get<std::string>();

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `params` field\n";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: no params field";
        return;
    }

    if (method_name == "store") {
        process_store(*params_it);
    } else if (method_name == "retrieve") {
        process_retrieve(*params_it);
    } else if (method_name == "get_snodes_for_pubkey") {
        process_snodes_by_pk(*params_it);
    } else {
        response_.result(http::status::bad_request);
        body_stream_ << "no method" << method_name << "\n";
        BOOST_LOG_TRIVIAL(error)
            << boost::format("Bad Request. Unknown method '%1%'") % method_name;
    }
}

void connection_t::register_deadline() {

    auto self = shared_from_this();

    deadline_.async_wait([self](error_code ec) {
        if (ec) {

            if (ec != boost::asio::error::operation_aborted) {
                log_error(ec);
            }

        } else {

            BOOST_LOG_TRIVIAL(error) << "socket timed out";
            // Close socket to cancel any outstanding operation.
            self->socket_.close(ec);
        }
    });
}

/// ============

} // namespace http_server

/// TODO: make generic, avoid message copy
HttpClientSession::HttpClientSession(boost::asio::io_context& ioc,
                                     const tcp::endpoint& ep,
                                     const std::shared_ptr<request_t>& req,
                                     http_callback_t&& cb)
    : ioc_(ioc), socket_(ioc), endpoint_(ep), callback_(cb),
      deadline_timer_(ioc), req_(req) {}

void HttpClientSession::on_connect() {

    BOOST_LOG_TRIVIAL(trace) << "on connect";
    http::async_write(socket_, *req_,
                      std::bind(&HttpClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpClientSession::on_write(error_code ec, size_t bytes_transferred) {

    BOOST_LOG_TRIVIAL(trace) << "on write";
    if (ec) {
        BOOST_LOG_TRIVIAL(error) << "Error on write, ec: " << ec.value()
                                 << ". Message: " << ec.message();
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    BOOST_LOG_TRIVIAL(trace)
        << "Successfully transferred " << bytes_transferred << " bytes";

    // Receive the HTTP response
    http::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(error_code ec, size_t bytes_transferred) {

    BOOST_LOG_TRIVIAL(trace)
        << "Successfully received " << bytes_transferred << " bytes";

    std::shared_ptr<std::string> body = nullptr;

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {
            body = std::make_shared<std::string>(res_.body());
        }

    } else {

        /// Do we need to handle `operation aborted` separately here (due to
        /// deadline timer)?
        BOOST_LOG_TRIVIAL(error)
            << "Error on read: " << ec.value() << ". Message: " << ec.message();
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
    }

    // Gracefully close the socket
    socket_.shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        BOOST_LOG_TRIVIAL(error)
            << "ec: " << ec.value() << ". Message: " << ec.message();
        return;
    }

    trigger_callback(SNodeError::NO_ERROR, std::move(body));

    // If we get here then the connection is closed gracefully
}

void HttpClientSession::start() {
    socket_.async_connect(
        endpoint_, [this, self = shared_from_this()](const error_code& ec) {
            /// TODO: I think I should just call again if ec == EINTR
            if (ec) {
                BOOST_LOG_TRIVIAL(error)
                    << boost::format(
                           "Could not connect to %1%, message: %2% (%3%)") %
                           endpoint_ % ec.message() % ec.value();
                trigger_callback(SNodeError::NO_REACH, nullptr);
                return;
            }

            self->on_connect();
        });

    deadline_timer_.expires_after(SESSION_TIME_LIMIT);
    deadline_timer_.async_wait(
        [self = shared_from_this()](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    log_error(ec);
                }
            } else {
                BOOST_LOG_TRIVIAL(error) << "client socket timed out";
                self->socket_.close();
            }
        });
}

void HttpClientSession::trigger_callback(SNodeError error,
                                         std::shared_ptr<std::string>&& body) {
    ioc_.post(std::bind(callback_, sn_response_t{error, body}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

/// We execute callback (if haven't already) here to make sure it is called
HttpClientSession::~HttpClientSession() {

    if (!used_callback_) {
        // If we destroy the session before posting the callback,
        // it must be due to some error
        ioc_.post(std::bind(callback_,
                            sn_response_t{SNodeError::ERROR_OTHER, nullptr}));
    }
}

} // namespace loki
