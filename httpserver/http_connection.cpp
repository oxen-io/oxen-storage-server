#include "http_connection.h"
#include "Database.hpp"
#include "Item.hpp"
#include "channel_encryption.hpp"
#include "rate_limiter.h"
#include "security.h"
#include "serialization.h"
#include "server_certificates.h"
#include "service_node.h"
#include "signature.h"
#include "utils.hpp"

#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <openssl/sha.h>
#include <sodium.h>
#include <sstream>
#include <string>
#include <thread>

#include <boost/beast/core/detail/base64.hpp>

using json = nlohmann::json;
using namespace std::chrono_literals;

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

/// +===========================================

static constexpr auto LOKI_EPHEMKEY_HEADER = "X-Loki-EphemKey";

using loki::storage::Item;

using error_code = boost::system::error_code;

namespace loki {

constexpr auto TEST_RETRY_PERIOD = std::chrono::milliseconds(50);

// Note: on the client side the limit is different
// as it is not encrypted/encoded there yet.
// The choice is somewhat arbitrary but it roughly
// corresponds to the client-side limit of 2000 chars
// of unencrypted message body in our experiments
// (rounded up)
constexpr size_t MAX_MESSAGE_BODY = 3100;

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
        LOKI_LOG(error,
                 "http: Failed to parse the IP address. Error code = {}. "
                 "Message: {}",
                 ec.value(), ec.message());
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

static std::string arr32_to_hex(const std::array<uint8_t, 32>& arr) {

    constexpr size_t res_len = 32 * 2 + 1;

    char hex[res_len];

    sodium_bin2hex(hex, res_len, arr.data(), 32);

    return std::string(hex);
}
// ======================== Lokid Client ========================
LokidClient::LokidClient(boost::asio::io_context& ioc, uint16_t port)
    : ioc_(ioc), lokid_rpc_port_(port) {}

void LokidClient::make_lokid_request(boost::string_view method,
                                     const nlohmann::json& params,
                                     http_callback_t&& cb) const {

    make_lokid_request(local_ip_, lokid_rpc_port_, method, params,
                       std::move(cb));
}

void LokidClient::make_lokid_request(const std::string& daemon_ip,
                                     const uint16_t daemon_port,
                                     boost::string_view method,
                                     const nlohmann::json& params,
                                     http_callback_t&& cb) const {

    auto req = std::make_shared<request_t>();

    const std::string target = "/json_rpc";

    nlohmann::json req_body;
    req_body["jsonrpc"] = "2.0";
    req_body["id"] = "0";
    req_body["method"] = method;
    req_body["params"] = params;

    req->body() = req_body.dump();
    req->method(http::verb::post);
    req->target(target);
    req->prepare_payload();

    LOKI_LOG(trace, "Making lokid request, method: {}", method.to_string());

    make_http_request(ioc_, daemon_ip, daemon_port, req, std::move(cb));
}
// =============================================================

namespace http_server {

// "Loop" forever accepting new connections.
static void
accept_connection(boost::asio::io_context& ioc,
                  boost::asio::ssl::context& ssl_ctx, tcp::acceptor& acceptor,
                  ServiceNode& sn,
                  ChannelEncryption<std::string>& channel_encryption,
                  RateLimiter& rate_limiter, const Security& security) {

    acceptor.async_accept([&](const error_code& ec, tcp::socket socket) {
        LOKI_LOG(trace, "connection accepted");
        if (!ec)
            std::make_shared<connection_t>(ioc, ssl_ctx, std::move(socket), sn,
                                           channel_encryption, rate_limiter,
                                           security)
                ->start();

        if (ec) {
            LOKI_LOG(error, "Could not accept a new connection {}: {}",
                     ec.value(), ec.message());
        }

        accept_connection(ioc, ssl_ctx, acceptor, sn, channel_encryption,
                          rate_limiter, security);
    });
}

void run(boost::asio::io_context& ioc, const std::string& ip, uint16_t port,
         const boost::filesystem::path& base_path, ServiceNode& sn,
         ChannelEncryption<std::string>& channel_encryption,
         RateLimiter& rate_limiter, Security& security) {

    LOKI_LOG(trace, "http server run");

    const auto address =
        boost::asio::ip::make_address(ip); /// throws if incorrect

    tcp::acceptor acceptor{ioc, {address, port}};

    ssl::context ssl_ctx{ssl::context::tlsv12};

    load_server_certificate(base_path, ssl_ctx);

    security.generate_cert_signature();

    accept_connection(ioc, ssl_ctx, acceptor, sn, channel_encryption,
                      rate_limiter, security);

    ioc.run();
}

/// ============ connection_t ============

connection_t::connection_t(boost::asio::io_context& ioc, ssl::context& ssl_ctx,
                           tcp::socket socket, ServiceNode& sn,
                           ChannelEncryption<std::string>& channel_encryption,
                           RateLimiter& rate_limiter, const Security& security)
    : ioc_(ioc), ssl_ctx_(ssl_ctx), socket_(std::move(socket)),
      stream_(socket_, ssl_ctx_), service_node_(sn),
      channel_cipher_(channel_encryption), rate_limiter_(rate_limiter),
      repeat_timer_(ioc),
      deadline_(ioc, SESSION_TIME_LIMIT), notification_ctx_{boost::none},
      security_(security) {

    static uint64_t instance_counter = 0;
    conn_idx = instance_counter++;

    LOKI_LOG(trace, "connection_t [{}]", conn_idx);

    start_timestamp_ = std::chrono::steady_clock::now();
}

connection_t::~connection_t() {

    // TODO: should check if we are still registered for
    // notifications, and deregister if so.

    // Safety net
    if (stream_.lowest_layer().is_open()) {
        LOKI_LOG(warn, "Client socket should be closed by this point, but "
                       "wasn't. Closing now.");
        stream_.lowest_layer().close();
    }

    LOKI_LOG(trace, "~connection_t [{}]", conn_idx);
}

void connection_t::start() {
    register_deadline();
    do_handshake();
}

void connection_t::do_handshake() {
    // Perform the SSL handshake
    stream_.async_handshake(ssl::stream_base::server,
                            std::bind(&connection_t::on_handshake,
                                      shared_from_this(),
                                      std::placeholders::_1));
}

void connection_t::on_handshake(boost::system::error_code ec) {
    if (ec) {
        LOKI_LOG(warn, "ssl handshake failed: {}", ec.message());
        deadline_.cancel();
        return;
    }

    read_request();
}

void connection_t::notify(boost::optional<const message_t&> msg) {

    if (!notification_ctx_) {
        LOKI_LOG(error,
                 "Trying to notify a connection without notification context");
        return;
    }

    if (msg) {
        LOKI_LOG(trace, "Processing message notification: {}", msg->data);
        // save messages, so we can access them once the timer event happens
        notification_ctx_->message = msg;
    }
    // the timer callback will be called once we complete the current callback
    notification_ctx_->timer.cancel();
}

// Asynchronously receive a complete request message.
void connection_t::read_request() {

    auto on_data = [self = shared_from_this()](error_code ec, size_t bytes_transferred) {
        LOKI_LOG(trace, "on data: {} bytes", bytes_transferred);

        if (ec) {
            LOKI_LOG(
                error,
                "Failed to read from a socket [{}: {}], connection idx: {}",
                ec.value(), ec.message(), self->conn_idx);
            self->deadline_.cancel();
            return;
        }

        // NOTE: this is blocking, we should make this asynchronous
        try {
            self->process_request();
        } catch (const std::exception& e) {
            LOKI_LOG(error, "Exception caught processing a request: {}",
                     e.what());
            self->body_stream_ << e.what();
        }

        if (!self->delay_response_) {
            self->write_response();
        }
    };

    http::async_read(stream_, buffer_, request_, on_data);
}

bool connection_t::validate_snode_request() {
    if (!parse_header(LOKI_SENDER_SNODE_PUBKEY_HEADER,
                      LOKI_SNODE_SIGNATURE_HEADER)) {
        LOKI_LOG(error, "Missing signature headers");
        return false;
    }
    const auto& signature = header_[LOKI_SNODE_SIGNATURE_HEADER];
    const auto& public_key_b32z = header_[LOKI_SENDER_SNODE_PUBKEY_HEADER];

    /// Known service node
    const std::string snode_address = public_key_b32z + ".snode";
    if (!service_node_.is_snode_address_known(snode_address)) {
        body_stream_ << "Unknown service node\n";
        LOKI_LOG(error, "Discarding signature from unknown service node: {}",
                 public_key_b32z);
        response_.result(http::status::unauthorized);
        return false;
    }

    if (!verify_signature(signature, public_key_b32z)) {
        constexpr auto msg = "Could not verify batch signature";
        LOKI_LOG(warn, "{}", msg);
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

void connection_t::process_storage_test_req(uint64_t height,
                                            const std::string& tester_addr,
                                            const std::string& msg_hash) {

    LOKI_LOG(trace, "Performing storage test, attempt: {}", repetition_count_);

    std::string answer;

    const MessageTestStatus status = service_node_.process_storage_test_req(
        height, tester_addr, msg_hash, answer);
    const auto elapsed_time =
        std::chrono::steady_clock::now() - start_timestamp_;
    if (status == MessageTestStatus::SUCCESS) {
        LOKI_LOG(
            debug, "Storage test success! Attempts: {}. Took {} ms",
            repetition_count_,
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time)
                .count());
        delay_response_ = true;
        body_stream_ << answer;
        response_.result(http::status::ok);
        this->write_response();
    } else if (status == MessageTestStatus::RETRY && elapsed_time < 1min) {
        delay_response_ = true;
        repetition_count_++;

        repeat_timer_.expires_after(TEST_RETRY_PERIOD);
        repeat_timer_.async_wait([self = shared_from_this(), height, msg_hash,
                                  tester_addr](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    LOKI_LOG(error,
                             "Repeat timer failed for storage test [{}: {}]",
                             ec.value(), ec.message());
                }
            } else {
                self->process_storage_test_req(height, tester_addr, msg_hash);
            }
        });

    } else {
        LOKI_LOG(error, "Failed storage test, tried {} times.",
                 repetition_count_);
        response_.result(http::status::bad_request);
        /// TODO: send a helpful error message
    }
}

void connection_t::process_swarm_req(boost::string_view target) {

#ifndef DISABLE_SNODE_SIGNATURE
    if (!validate_snode_request()) {
        return;
    }
#endif

    response_.set(LOKI_SNODE_SIGNATURE_HEADER, security_.get_cert_signature());

    if (target == "/swarms/push_batch/v1") {

        response_.result(http::status::ok);
        service_node_.process_push_batch(request_.body());

    } else if (target == "/swarms/storage_test/v1") {
        LOKI_LOG(debug, "Got storage test request");

        using nlohmann::json;

        const json body = json::parse(request_.body(), nullptr, false);

        if (body == nlohmann::detail::value_t::discarded) {
            LOKI_LOG(error, "Bad snode test request: invalid json");
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
            LOKI_LOG(error, "Bad snode test request: missing fields in json");
            return;
        }

        const auto it = header_.find(LOKI_SENDER_SNODE_PUBKEY_HEADER);
        if (it != header_.end()) {
            std::string& tester_pk = it->second;
            tester_pk.append(".snode");
            this->process_storage_test_req(blk_height, tester_pk, msg_hash);
        } else {
            LOKI_LOG(warn, "Ignoring test request, no pubkey present");
        }
    } else if (target == "/swarms/blockchain_test/v1") {
        LOKI_LOG(debug, "Got blockchain test request");

        using nlohmann::json;

        const json body = json::parse(request_.body(), nullptr, false);

        if (body.is_discarded()) {
            LOKI_LOG(error, "Bad snode test request: invalid json");
            response_.result(http::status::bad_request);
            return;
        }

        bc_test_params_t params;

        try {
            params.max_height = body.at("max_height").get<uint64_t>();
            params.seed = body.at("seed").get<uint64_t>();
        } catch (...) {
            response_.result(http::status::bad_request);
            LOKI_LOG(error, "Bad snode test request: missing fields in json");
            return;
        }

        delay_response_ = true;

        auto callback = [this](blockchain_test_answer_t answer) {
            this->response_.result(http::status::ok);

            nlohmann::json json_res;
            json_res["res_height"] = answer.res_height;

            this->body_stream_ << json_res.dump();
            this->write_response();
        };

        service_node_.perform_blockchain_test(params, callback);
    } else if (target == "/swarms/push/v1") {

        LOKI_LOG(trace, "swarms/push");

        /// NOTE:: we only expect one message here, but
        /// for now lets reuse the function we already have
        std::vector<message_t> messages = deserialize_messages(request_.body());
        assert(messages.size() == 1);

        service_node_.process_push(messages.front());

        response_.result(http::status::ok);
    }
}

// Determine what needs to be done with the request message.
void connection_t::process_request() {

    /// This method is responsible for filling out response_

    LOKI_LOG(trace, "process request");
    response_.version(request_.version());
    response_.keep_alive(false);

    /// TODO: make sure that we always send a response!

    response_.result(http::status::internal_server_error);

    const auto target = request_.target();
    switch (request_.method()) {
    case http::verb::post:
        if (!service_node_.snode_ready(boost::none)) {
            LOKI_LOG(debug, "Ignoring post request: storage server not ready");
            response_.result(http::status::service_unavailable);
            break;
        }
        if (target == "/storage_rpc/v1") {
            /// Store/load from clients
            LOKI_LOG(trace, "got /storage_rpc/v1");

            try {
                process_client_req();
            } catch (std::exception& e) {
                response_.result(http::status::internal_server_error);
                LOKI_LOG(error,
                         "exception caught while processing client request: {}",
                         e.what());
            }

            // TODO: parse target (once) to determine if it is a "swarms" call
        } else if (target == "/swarms/push/v1") {
            this->process_swarm_req(target);
        } else if (target == "/swarms/push_batch/v1") {
            this->process_swarm_req(target);
        } else if (target == "/swarms/storage_test/v1") {

            this->process_swarm_req(target);

        } else if (target == "/swarms/blockchain_test/v1") {

            this->process_swarm_req(target);

        }
#ifdef INTEGRATION_TEST
        else if (target == "/retrieve_all") {
            process_retrieve_all();
        } else if (target == "/quit") {
            LOKI_LOG(info, "got /quit request");
            // a bit of a hack: sending response manually
            delay_response_ = true;
            response_.result(http::status::ok);
            write_response();
            ioc_.stop();
        }
#endif
        else {
            LOKI_LOG(error, "unknown target for POST: {}", target.to_string());
            response_.result(http::status::not_found);
        }
        break;
    case http::verb::get:

        if (target == "/get_stats/v1") {
            this->on_get_stats();
        } else {
            LOKI_LOG(error, "unknown target for GET: {}", target.to_string());
            response_.result(http::status::not_found);
        }
        break;
    default:
        LOKI_LOG(error, "bad request");
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
    // TODO: do we need to separately handle the case where we can't find the key?
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
            LOKI_LOG(error,
                     "Internal Server Error. Could not encrypt response for {}",
                     obfuscate_pubkey(ephemKey));
        }
    }
#else
    response_.body() = body_stream_.str();
#endif

    response_.set(http::field::content_length, response_.body().size());

    /// This attempts to write all data to a stream
    /// TODO: handle the case when we are trying to send too much
    http::async_write(stream_, response_, [self = shared_from_this()](error_code ec, size_t) {

        if (ec && ec != boost::asio::error::operation_aborted) {
            LOKI_LOG(error, "Failed to write to a socket: {}", ec.message());
        }

        self->do_close();
        /// Is it too early to cancel the deadline here?
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
        snode["address"] = sn.sn_address();
        snode["port"] = std::to_string(sn.port());
        snode["ip"] = sn.ip();
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
            LOKI_LOG(error, "Bad client request: no `{}` field", field);
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
        LOKI_LOG(error, "Pubkey must be 66 characters long");
        return;
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        response_.result(http::status::bad_request);
        body_stream_ << "Message body exceeds maximum allowed length of "
                     << MAX_MESSAGE_BODY << "\n";
        LOKI_LOG(error, "Message body too long: {}", data.size());
        return;
    }

    if (!service_node_.is_pubkey_for_us(pubKey)) {
        handle_wrong_swarm(pubKey);
        return;
    }

#ifdef INTEGRATION_TEST
    LOKI_LOG(trace, "store body: ", data);
#endif

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        response_.result(http::status::forbidden);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Provided TTL is not valid.\n";
        LOKI_LOG(error, "Forbidden. Invalid TTL: {}", ttl);
        return;
    }
    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        response_.result(http::status::not_acceptable);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Timestamp error: check your clock\n";
        LOKI_LOG(error, "Forbidden. Invalid Timestamp: {}", timestamp);
        return;
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;

    const bool valid_pow =
        checkPoW(nonce, timestamp, ttl, pubKey, data, messageHash,
                 service_node_.get_curr_pow_difficulty());
#ifndef DISABLE_POW
    if (!valid_pow) {
        response_.result(432);
        response_.set(http::field::content_type, "application/json");

        json res_body;
        res_body["difficulty"] = service_node_.get_curr_pow_difficulty();
        LOKI_LOG(error, "Forbidden. Invalid PoW nonce: {}", nonce);

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
        LOKI_LOG(error, "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pubKey));
        return;
    }

    if (!success) {
        response_.result(http::status::service_unavailable);
        response_.set(http::field::content_type, "text/plain");
        /// This is not the only reason for faliure
        body_stream_ << "Service node is initializing\n";
        LOKI_LOG(warn, "Service node is initializing");
        return;
    }

    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");
    json res_body;
    res_body["difficulty"] = service_node_.get_curr_pow_difficulty();
    body_stream_ << res_body.dump();
    LOKI_LOG(trace, "Successfully stored message for {}",
             obfuscate_pubkey(pubKey));
}

void connection_t::process_snodes_by_pk(const json& params) {

    if (!params.contains("pubKey")) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `pubKey` field\n";
        LOKI_LOG(error, "Bad client request: no `pubKey` field");
        return;
    }

    auto pubKey = params["pubKey"].get<std::string>();

    if (pubKey.size() != 66) {
        response_.result(http::status::bad_request);
        body_stream_ << "Pubkey must be 66 characters long\n";
        LOKI_LOG(error, "Pubkey must be 66 characters long ");
        return;
    }

    const std::vector<sn_record_t> nodes =
        service_node_.get_snodes_by_pk(pubKey);
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

    const std::vector<sn_record_t> nodes =
        service_node_.get_snodes_by_pk(pubKey);
    const json res_body = snodes_to_json(nodes);

    response_.result(http::status::misdirected_request);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    body_stream_ << res_body.dump();
    LOKI_LOG(info, "Client request for different swarm received");
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
        LOKI_LOG(error,
                 "Internal Server Error. Could not retrieve messages for {}",
                 obfuscate_pubkey(pk));
        return;
    }

    const bool lp_requested =
        request_.find("X-Loki-Long-Poll") != request_.end();

    if (!items.empty()) {
        LOKI_LOG(trace, "Successfully retrieved messages for {}",
                 obfuscate_pubkey(pk));
    }

    if (items.empty() && lp_requested) {

        auto self = shared_from_this();

        // Instead of responding immediately, we delay the response
        // until new data arrives for this PubKey
        service_node_.register_listener(pk, self);

        notification_ctx_ = notification_context_t{
            boost::asio::steady_timer{ioc_}, boost::none, pk};

        notification_ctx_->timer.expires_after(LONG_POLL_TIMEOUT);
        notification_ctx_->timer.async_wait([=](const error_code& ec) {
            if (ec == boost::asio::error::operation_aborted) {
                LOKI_LOG(trace, "Notification timer manually triggered");
                // we use timer cancellation as notification mechanism
                std::vector<message_t> items;
                auto msg = notification_ctx_->message;
                if (msg) {
                    items.push_back(*msg);
                }

                respond_with_messages(items);
            } else {
                LOKI_LOG(trace, "Notification timer expired");
                // If we are here, the notification timer expired
                // with no messages ready
                respond_with_messages<Item>({});
            }

            service_node_.remove_listener(pk, self.get());
        });

    } else {
        respond_with_messages(items);
    }
}

void connection_t::process_retrieve(const json& params) {

    service_node_.all_stats_.client_retrieve_requests++;

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            body_stream_ << boost::format("invalid json: no `%1%` field\n") %
                                field;
            LOKI_LOG(error, "Bad client request: no `{}` field", field);
            return;
        }
    }

    const auto pub_key = params["pubKey"].get<std::string>();
    const auto last_hash = params["lastHash"].get<std::string>();

    if (!service_node_.is_pubkey_for_us(pub_key)) {
        handle_wrong_swarm(pub_key);
        return;
    }

    // we are going to send the response anynchronously
    // once we have new data
    delay_response_ = true;

    poll_db(pub_key, last_hash);
}

void connection_t::process_client_req() {
    std::string plain_text = request_.body();
    const std::string client_ip =
        socket_.remote_endpoint().address().to_string();
    if (rate_limiter_.should_rate_limit_client(client_ip)) {
        response_.result(http::status::too_many_requests);
        LOKI_LOG(error, "Rate limiting client request.");
        return;
    }

#ifndef DISABLE_ENCRYPTION
    if (!parse_header(LOKI_EPHEMKEY_HEADER)) {
        LOKI_LOG(error, "Could not parse headers");
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
        LOKI_LOG(error, "Bad Request. Could not decrypt body");
        return;
    }
#endif

    const json body = json::parse(plain_text, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json\n";
        LOKI_LOG(error, "Bad client request: invalid json");
        return;
    }

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `method` field\n";
        LOKI_LOG(error, "Bad client request: no method field");
        return;
    }

    const auto method_name = method_it->get<std::string>();

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `params` field\n";
        LOKI_LOG(error, "Bad client request: no params field");
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
        LOKI_LOG(error, "Bad Request. Unknown method '{}'", method_name);
    }
}

void connection_t::register_deadline() {

    auto self = shared_from_this();

    // Note: deadline callback captures a shared pointer to this, so
    // the connection will not be destroyed until the timer goes off.
    // If we want to destroy it earlier, we need to manually cancel the timer.
    deadline_.async_wait([self = std::move(self)](error_code ec) {
        const bool cancelled = (ec && ec == boost::asio::error::operation_aborted);

        if (cancelled)
            return;

        // Note: cancelled timer does absolutely nothing, so we need to make sure
        // we close the socket (and unsubscribe from notifications) elsewhere if
        // we cancel it.
        if (ec) {
            LOKI_LOG(error, "Deadline timer error [{}]: {}", ec.value(),
                     ec.message());
        }

        // TODO: move this to do_close?
        if (self->notification_ctx_) {
            self->service_node_.remove_listener(
                self->notification_ctx_->pubkey, self.get());
        }
        LOKI_LOG(debug, "Closing [connection_t] socket due to timeout");
        self->do_close();
    });
}

void connection_t::do_close() {
    // Perform the SSL shutdown
    stream_.async_shutdown(std::bind(
        &connection_t::on_shutdown, shared_from_this(), std::placeholders::_1));
}

void connection_t::on_shutdown(boost::system::error_code ec) {
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }
    if (ec)
        LOKI_LOG(error, "Could not close ssl stream gracefully, ec: {}", ec.message());

    stream_.lowest_layer().close();
}

void connection_t::on_get_stats() {
    this->body_stream_ << service_node_.get_stats();
    this->response_.result(http::status::ok);
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

    LOKI_LOG(trace, "on connect");
    http::async_write(socket_, *req_,
                      std::bind(&HttpClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpClientSession::on_write(error_code ec, size_t bytes_transferred) {

    LOKI_LOG(trace, "on write");
    if (ec) {
        LOKI_LOG(error, "Error on write, ec: {}. Message: {}", ec.value(),
                 ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    LOKI_LOG(trace, "Successfully transferred {} bytes", bytes_transferred);

    // Receive the HTTP response
    http::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(error_code ec, size_t bytes_transferred) {

    if (!ec || (ec == http::error::end_of_stream)) {

        LOKI_LOG(trace, "Successfully received {} bytes.", bytes_transferred);

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {
            std::shared_ptr<std::string> body =
                std::make_shared<std::string>(res_.body());
            trigger_callback(SNodeError::NO_ERROR, std::move(body));
        } else {
            LOKI_LOG(error, "Http request failed, error code: {}",
                     res_.result_int());
            trigger_callback(SNodeError::HTTP_ERROR, nullptr);
        }

    } else {

        if (ec != boost::asio::error::operation_aborted) {
            LOKI_LOG(error, "Error on read: {}. Message: {}", ec.value(),
                     ec.message());
        }
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
    }
}

void HttpClientSession::start() {
    socket_.async_connect(endpoint_, [this, self = shared_from_this()](
                                         const error_code& ec) {
        /// TODO: I think I should just call again if ec == EINTR
        if (ec) {
            LOKI_LOG(
                error,
                "[http client]: could not connect to {}:{}, message: {} ({})",
                endpoint_.address().to_string(), endpoint_.port(), ec.message(),
                ec.value());
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
                    LOKI_LOG(
                        error,
                        "Deadline timer failed in http client session [{}: {}]",
                        ec.value(), ec.message());
                }
            } else {
                LOKI_LOG(error, "client socket timed out");
                self->socket_.close();
            }
        });
}

void HttpClientSession::trigger_callback(SNodeError error,
                                         std::shared_ptr<std::string>&& body) {
    LOKI_LOG(trace, "Trigger callback");
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

    if (!socket_.is_open()) {
        LOKI_LOG(debug, "Socket is already closed");
        return;
    }

    error_code ec;

    /// From boost documentation: "For portable behaviour with respect to
    /// graceful closure of a connected socket, call shutdown() before closing
    /// the socket."
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {
        LOKI_LOG(error, "Socket shutdown failure [{}: {}]", ec.value(),
                 ec.message());
    }

    socket_.close(ec);

    if (ec) {
        LOKI_LOG(error, "On close socket [{}: {}]", ec.value(), ec.message());
    }
}

} // namespace loki
