#include "http_connection.h"
#include "Database.hpp"
#include "Item.hpp"
#include "channel_encryption.hpp"
#include "dev_sink.h"
#include "net_stats.h"
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

using json = nlohmann::json;
using namespace std::chrono_literals;

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

/// +===========================================

static constexpr auto LOKI_EPHEMKEY_HEADER = "X-Loki-EphemKey";
static constexpr auto LOKI_LONG_POLL_HEADER = "X-Loki-Long-Poll";

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
                 "http: Failed to parse the IP address <{}>. Error code = {}. "
                 "Message: {}",
                 sn_address, ec.value(), ec.message());
        return;
    }
    while (destination != tcp::resolver::iterator()) {
        const tcp::endpoint thisEndpoint = (destination++)->endpoint();
        if (!thisEndpoint.address().is_v4()) {
            continue;
        }
        endpoint = thisEndpoint;
    }
    endpoint.port(port);

    auto session =
        std::make_shared<HttpClientSession>(ioc, endpoint, req, std::move(cb));

    session->start();
}

// ======================== Lokid Client ========================
LokidClient::LokidClient(boost::asio::io_context& ioc, std::string ip, uint16_t port)
    : ioc_(ioc), lokid_rpc_ip_(std::move(ip)), lokid_rpc_port_(port) {}

void LokidClient::make_lokid_request(boost::string_view method,
                                     const nlohmann::json& params,
                                     http_callback_t&& cb) const {

    make_custom_lokid_request(lokid_rpc_ip_, lokid_rpc_port_, method, params,
                              std::move(cb));
}

void LokidClient::make_custom_lokid_request(const std::string& daemon_ip,
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

static bool validateHexKey(const std::string& key) {
    return key.size() == 2 * loki::KEY_LENGTH &&
           std::all_of(key.begin(), key.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

std::tuple<private_key_t, private_key_ed25519_t, private_key_t>
LokidClient::wait_for_privkey() {
    // fetch SN private key from lokid; do this synchronously because we can't finish startup
    // until we have it.
    loki::private_key_t private_key;
    loki::private_key_ed25519_t private_key_ed;
    loki::private_key_t private_key_x;
    LOKI_LOG(info, "Retrieving SN key from lokid");
    boost::asio::steady_timer delay{ioc_};
    std::function<void(loki::sn_response_t &&res)> key_fetch;
    key_fetch = [&](loki::sn_response_t res) {
        try {
            if (res.error_code != loki::SNodeError::NO_ERROR)
                throw std::runtime_error(loki::error_string(res.error_code));
            else if (!res.body)
                throw std::runtime_error("empty body");
            else {
                auto r = nlohmann::json::parse(*res.body);
                const auto &legacy_privkey = r.at("result").at("service_node_privkey").get_ref<const std::string &>();
                const auto &privkey_ed = r.at("result").at("service_node_ed25519_privkey").get_ref<const std::string &>();
                const auto &privkey_x = r.at("result").at("service_node_x25519_privkey").get_ref<const std::string &>();
                if (!validateHexKey(legacy_privkey) || !validateHexKey(privkey_ed) || !validateHexKey(privkey_x))
                    throw std::runtime_error("returned value is not hex");
                else {
                    private_key = loki::lokidKeyFromHex(legacy_privkey);
                    // TODO: check that one is derived from the other as a sanity check?
                    private_key_ed = private_key_ed25519_t::from_hex(privkey_ed);
                    private_key_x = loki::lokidKeyFromHex(privkey_x);
                    // run out of work, which will end the event loop
                }
            }
        } catch (const std::exception &e) {
            LOKI_LOG(critical, "Error retrieving SN privkey from lokid @ {}:{}: {}.  Is lokid running?  Retrying in 5s",
                     lokid_rpc_ip_, lokid_rpc_port_, e.what());

            delay.expires_after(std::chrono::seconds{5});
            delay.async_wait([this, &key_fetch](const boost::system::error_code &) {
                    make_lokid_request("get_service_node_privkey", {}, key_fetch); });
        }
    };
    make_lokid_request("get_service_node_privkey", {}, key_fetch);
    ioc_.run(); // runs until we get success above
    ioc_.restart();

    return {private_key, private_key_ed, private_key_x};
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

    static boost::asio::steady_timer acceptor_timer(ioc);
    constexpr std::chrono::milliseconds ACCEPT_DELAY = 50ms;

    acceptor.async_accept([&](const error_code& ec, tcp::socket socket) {
        LOKI_LOG(trace, "connection accepted");
        if (!ec) {

            std::make_shared<connection_t>(ioc, ssl_ctx, std::move(socket), sn,
                                           channel_encryption, rate_limiter,
                                           security)
                ->start();

            accept_connection(ioc, ssl_ctx, acceptor, sn, channel_encryption,
                              rate_limiter, security);
        } else {

            // TODO: remove this once we confirmed that there is
            // no more socket leaking
            if (ec == boost::system::errc::too_many_files_open) {
                LOKI_LOG(critical, "Too many open files, aborting");
                abort();
            }

            LOKI_LOG(
                error,
                "Could not accept a new connection {}: {}. Will only start "
                "accepting new connections after a short delay.",
                ec.value(), ec.message());

            // If we fail here we are unlikely to be able to accept a new
            // connection immediately, hence the delay
            acceptor_timer.expires_after(ACCEPT_DELAY);
            acceptor_timer.async_wait([&](const error_code& ec) {
                if (ec && ec != boost::asio::error::operation_aborted) {
                    // Not sure how to recover here, so it is probably the
                    // safest to simply abort and let the launcher/systemd
                    // restart us
                    abort();
                }

                accept_connection(ioc, ssl_ctx, acceptor, sn,
                                  channel_encryption, rate_limiter, security);
            });
        }
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

    get_net_stats().connections_in++;

    LOKI_LOG(trace, "connection_t [{}]", conn_idx);

    start_timestamp_ = std::chrono::steady_clock::now();
}

connection_t::~connection_t() {

    // Safety net
    if (stream_.lowest_layer().is_open()) {
        LOKI_LOG(debug, "Client socket should be closed by this point, but "
                        "wasn't. Closing now.");
        stream_.lowest_layer().close();
    }

    get_net_stats().connections_in--;

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

    const auto sockfd = stream_.lowest_layer().native_handle();
    LOKI_LOG(debug, "Open https socket: {}", sockfd);
    get_net_stats().record_socket_open(sockfd);
    if (ec) {
        LOKI_LOG(warn, "ssl handshake failed: ec: {} ({})", ec.value(), ec.message());
        this->clean_up();
        deadline_.cancel();
        return;
    }

    read_request();
}

void connection_t::clean_up() {

    this->do_close();

    if (this->notification_ctx_) {
        this->service_node_.remove_listener(this->notification_ctx_->pubkey,
                                            this);
    }
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

    auto on_data = [self = shared_from_this()](error_code ec,
                                               size_t bytes_transferred) {
        LOKI_LOG(trace, "on data: {} bytes", bytes_transferred);

        if (ec) {
            LOKI_LOG(
                error,
                "Failed to read from a socket [{}: {}], connection idx: {}",
                ec.value(), ec.message(), self->conn_idx);
            self->clean_up();
            self->deadline_.cancel();
            return;
        }

        // NOTE: this is blocking, we should make this asynchronous
        try {
            self->process_request();
        } catch (const std::exception& e) {
            LOKI_LOG(critical, "Exception caught processing a request: {}",
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
        LOKI_LOG(debug, "Missing signature headers for a Service Node request");
        return false;
    }
    const auto& signature = header_[LOKI_SNODE_SIGNATURE_HEADER];
    const auto& public_key_b32z = header_[LOKI_SENDER_SNODE_PUBKEY_HEADER];

    /// Known service node
    const std::string snode_address = public_key_b32z + ".snode";
    if (!service_node_.is_snode_address_known(snode_address)) {
        body_stream_ << "Unknown service node\n";
        LOKI_LOG(debug, "Discarding signature from unknown service node: {}",
                 public_key_b32z);
        response_.result(http::status::unauthorized);
        return false;
    }

    if (!verify_signature(signature, public_key_b32z)) {
        constexpr auto msg = "Could not verify batch signature";
        LOKI_LOG(debug, "{}", msg);
        body_stream_ << msg;
        response_.result(http::status::unauthorized);
        return false;
    }
    if (rate_limiter_.should_rate_limit(public_key_b32z)) {
        this->body_stream_ << "Too many requests\n";
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
                                            const std::string& tester_pk,
                                            const std::string& msg_hash) {

    LOKI_LOG(trace, "Performing storage test, attempt: {}", repetition_count_);

    std::string answer;

    /// TODO: we never actually test that `height` is within any reasonable
    /// time window (or that it is not repeated multiple times), we should do that!
    /// This is done implicitly to some degree using `block_hashes_cache_`, which
    /// holds a limited number of recent blocks only and fails if an earlier block
    /// is requested
    const MessageTestStatus status = service_node_.process_storage_test_req(
        height, tester_pk, msg_hash, answer);
    const auto elapsed_time =
        std::chrono::steady_clock::now() - start_timestamp_;
    if (status == MessageTestStatus::SUCCESS) {
        LOKI_LOG(
            debug, "Storage test success! Attempts: {}. Took {} ms",
            repetition_count_,
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time)
                .count());
        delay_response_ = true;

        nlohmann::json json_res;
        json_res["status"] = "OK";
        json_res["value"] = answer;

        this->body_stream_ << json_res.dump();

        response_.result(http::status::ok);
        this->write_response();
    } else if (status == MessageTestStatus::RETRY && elapsed_time < 1min) {
        delay_response_ = true;
        repetition_count_++;

        repeat_timer_.expires_after(TEST_RETRY_PERIOD);
        repeat_timer_.async_wait([self = shared_from_this(), height, msg_hash,
                                  tester_pk](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    LOKI_LOG(error,
                             "Repeat timer failed for storage test [{}: {}]",
                             ec.value(), ec.message());
                }
            } else {
                self->process_storage_test_req(height, tester_pk, msg_hash);
            }
        });

    } else if (status == MessageTestStatus::WRONG_REQ) {
        nlohmann::json json_res;
        json_res["status"] = "wrong request";
        this->body_stream_ << json_res.dump();
        response_.result(http::status::ok);
    } else {
        LOKI_LOG(error, "Failed storage test, tried {} times.",
                 repetition_count_);
        nlohmann::json json_res;
        json_res["status"] = "other";
        this->body_stream_ << json_res.dump();
        response_.result(http::status::ok);
    }
}

void connection_t::process_blockchain_test_req(uint64_t,
                                               const std::string& tester_pk,
                                               bc_test_params_t params) {

    // Note: `height` can be 0, which is the default value for old SS, allowed
    // pre HF13

    LOKI_LOG(debug, "Performing blockchain test");

    auto callback = [this](blockchain_test_answer_t answer) {
        this->response_.result(http::status::ok);

        nlohmann::json json_res;
        json_res["res_height"] = answer.res_height;

        this->body_stream_ << json_res.dump();
        this->write_response();
    };

    /// TODO: this should first check if tester/testee are correct! (use `height`)
    service_node_.perform_blockchain_test(params, std::move(callback));
}

static void print_headers(const request_t& req) {
    LOKI_LOG(info, "HEADERS:");
    for (const auto &field: req) {
        LOKI_LOG(info, "    [{}]: {}", field.name_string(), field.value());
    }
}

void connection_t::process_proxy_req(boost::string_view target) {

    LOKI_LOG(debug, "Processing proxy request: we are first hop");

#ifdef INTEGRATION_TEST
    print_headers(this->request_);
#endif

    delay_response_ = true;

    if (!parse_header(LOKI_SENDER_KEY_HEADER,
                      LOKI_TARGET_SNODE_KEY)) {
        LOKI_LOG(debug, "Missing headers for a proxy request");
        return;
    }

    const auto& sender_key = header_[LOKI_SENDER_KEY_HEADER];
    const auto& target_snode_key = header_[LOKI_TARGET_SNODE_KEY];

    service_node_.process_proxy_req(this->request_.body(), sender_key, target_snode_key, [this] (sn_response_t res) {

        if (res.raw_response) {
            this->response_ = *res.raw_response;
        }

        this->write_response();
    });
}

void connection_t::process_swarm_req(boost::string_view target) {

    // allow ping request as a quick workaround (and they are cheap)
    if (!validate_snode_request() && (target != "/swarms/ping_test/v1")) {
        return;
    }

    response_.set(LOKI_SNODE_SIGNATURE_HEADER, security_.get_cert_signature());

    if (target == "/swarms/push_batch/v1") {

        response_.result(http::status::ok);
        service_node_.process_push_batch(request_.body());

    } else if (target == "/swarms/storage_test/v1") {

        /// Set to "bad request" by default
        response_.result(http::status::bad_request);
        LOKI_LOG(debug, "Got storage test request");

        using nlohmann::json;

        const json body = json::parse(request_.body(), nullptr, false);

        if (body == nlohmann::detail::value_t::discarded) {
            LOKI_LOG(debug, "Bad snode test request: invalid json");
            body_stream_ << "invalid json\n";
            response_.result(http::status::bad_request);
            return;
        }

        uint64_t blk_height;
        std::string msg_hash;

        try {
            blk_height = body.at("height").get<uint64_t>();
            msg_hash = body.at("hash").get<std::string>();
        } catch (...) {
            this->body_stream_
                << "Bad snode test request: missing fields in json";
            response_.result(http::status::bad_request);
            LOKI_LOG(debug, "Bad snode test request: missing fields in json");
            return;
        }

        const auto it = header_.find(LOKI_SENDER_SNODE_PUBKEY_HEADER);
        if (it != header_.end()) {
            const std::string& tester_pk = it->second;
            this->process_storage_test_req(blk_height, tester_pk, msg_hash);
        } else {
            LOKI_LOG(debug, "Ignoring test request, no pubkey present");
        }
    } else if (target == "/swarms/blockchain_test/v1") {
        LOKI_LOG(debug, "Got blockchain test request");

        using nlohmann::json;

        const json body = json::parse(request_.body(), nullptr, false);

        if (body.is_discarded()) {
            LOKI_LOG(debug, "Bad snode test request: invalid json");
            response_.result(http::status::bad_request);
            return;
        }

        bc_test_params_t params;

        // Height that should be used to check derive tester/testee
        uint64_t height = 0;

        try {
            params.max_height = body.at("max_height").get<uint64_t>();
            params.seed = body.at("seed").get<uint64_t>();

            if (body.find("height") != body.end()) {
                height = body.at("height").get<uint64_t>();
            } else {
                LOKI_LOG(debug, "No tester height, defaulting to {}", height);
            }
        } catch (...) {
            response_.result(http::status::bad_request);
            LOKI_LOG(debug, "Bad snode test request: missing fields in json");
            return;
        }

        /// TODO: only check pubkey field once (in validate snode req)
        const auto it = header_.find(LOKI_SENDER_SNODE_PUBKEY_HEADER);
        if (it != header_.end()) {
            const std::string& tester_pk = it->second;
            delay_response_ = true;
            this->process_blockchain_test_req(height, tester_pk, params);
        } else {
            LOKI_LOG(debug, "Ignoring test request, no pubkey present");
        }

    } else if (target == "/swarms/ping_test/v1") {
        LOKI_LOG(debug, "Received ping_test");
        response_.result(http::status::ok);
    } else if (target == "/swarms/push/v1") {

        LOKI_LOG(trace, "swarms/push");

        /// NOTE:: we only expect one message here, but
        /// for now lets reuse the function we already have
        std::vector<message_t> messages = deserialize_messages(request_.body());
        assert(messages.size() == 1);

        service_node_.process_push(messages.front());

        response_.result(http::status::ok);
    } else if (target == "/swarms/proxy_exit") {
        LOKI_LOG(debug, "Processing proxy request: we are the destination node");

#ifdef INTEGRATION_TEST
        print_headers(this->request_);
#endif

        const auto it = this->request_.find(LOKI_SENDER_KEY_HEADER);
        if (it != this->request_.end()) {

            const std::string key = {it->value().data(), it->value().size()};
            const auto plaintext = this->channel_cipher_.decrypt(this->request_.body(), key);

            try {
                const json req = json::parse(plaintext, nullptr, true);

                const auto body = req.at("body").get<std::string>();

                this->response_modifier_ = [this, key](response_t& res) {

                    nlohmann::json json_res;

                    json_res["status"] = res.result_int();
                    json_res["body"] = res.body();

                    nlohmann::json headers;

                    for (const auto &field: res) {
                        std::string name = field.name_string().to_string();
                        headers[std::move(name)] = field.value();
                    }

                    json_res["headers"] = headers;

                    const std::string res_body = json_res.dump();

                    res.body() = util::base64_encode(this->channel_cipher_.encrypt(res_body, key));
                    res.result(http::status::ok);
                };

                // TODO: copy all other headers from decrypted body to header_?
                const auto headers_it = req.find("headers");
                if (headers_it != req.end()) {

                    const auto long_poll_it = headers_it->find(LOKI_LONG_POLL_HEADER);
                    if (long_poll_it != headers_it->end()) {
                        const bool val = long_poll_it->get<bool>();
                        LOKI_LOG(info, "field: {}: {}", LOKI_LONG_POLL_HEADER, val);
                        this->header_.insert({LOKI_LONG_POLL_HEADER, val ? "true" : "false"});
                    }

                }

                this->process_client_req(body);


            } catch (std::exception& e) {
                LOKI_LOG(error, "JSON parsing error: {}", e.what());
            }
        }

    }
}

// Determine what needs to be done with the request message.
void connection_t::process_request() {

    /// This method is responsible for filling out response_

    LOKI_LOG(trace, "connection_t::process_request");
    response_.version(request_.version());
    response_.keep_alive(false);

    /// TODO: make sure that we always send a response!

    response_.result(http::status::internal_server_error);

    const auto target = request_.target();
    switch (request_.method()) {
    case http::verb::post: {
        std::string reason;

        // Respond to ping even if we are not ready
        if (target == "/swarms/ping_test/v1") {
            this->process_swarm_req(target);
            break;
        }
        if (!service_node_.snode_ready(reason)) {
            LOKI_LOG(debug,
                     "Ignoring post request; storage server not ready: {}",
                     reason);
            response_.result(http::status::service_unavailable);
            body_stream_ << fmt::format("Service node is not ready: {}\n",
                                        reason);
            break;
        }
        if (target == "/storage_rpc/v1") {
            /// Store/load from clients
            LOKI_LOG(trace, "POST /storage_rpc/v1");

            try {
                process_client_req_rate_limited();
            } catch (std::exception& e) {
                this->body_stream_ << fmt::format(
                    "Exception caught while processing client request: {}",
                    e.what());
                response_.result(http::status::internal_server_error);
                LOKI_LOG(critical,
                         "Exception caught while processing client request: {}",
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

        } else if (target == "/proxy") {
            this->process_proxy_req(target);
        } else if (target == "/swarms/proxy_exit") {
            this->process_swarm_req(target);
        }
#ifdef INTEGRATION_TEST
        else if (target == "/retrieve_all") {
            process_retrieve_all();
        } else if (target == "/quit") {
            LOKI_LOG(info, "POST /quit");
            // a bit of a hack: sending response manually
            delay_response_ = true;
            response_.result(http::status::ok);
            write_response();
            ioc_.stop();
        } else if (target == "/sleep") {
            ioc_.post([]() {
                LOKI_LOG(warn, "Sleeping for some time...");
                std::this_thread::sleep_for(std::chrono::seconds(30));
            });
            response_.result(http::status::ok);
        }
#endif
        else {
            LOKI_LOG(debug, "unknown target for POST: {}", target.to_string());
            this->body_stream_ << fmt::format("unknown target for POST: {}",
                                              target.to_string());
            response_.result(http::status::not_found);
        }
        break;
    }
    case http::verb::get:

        if (target == "/get_stats/v1") {
            this->on_get_stats();
        } else if (target == "/get_logs/v1") {
            this->on_get_logs();
        } else {
            this->body_stream_ << fmt::format("unknown target for GET: {}",
                                              target.to_string());
            LOKI_LOG(debug, "unknown target for GET: {}", target.to_string());
            response_.result(http::status::not_found);
        }
        break;
    default:
        LOKI_LOG(debug, "bad request");
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
    // TODO: do we need to separately handle the case where we can't find the
    // key?
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
            LOKI_LOG(critical,
                     "Internal Server Error. Could not encrypt response for {}",
                     obfuscate_pubkey(ephemKey));
        }
    }
#else

    const std::string body_stream = body_stream_.str();

    if (!body_stream.empty()) {

        if (!response_.body().empty()) {
            LOKI_LOG(debug, "Overwritting non-empty body in response!");
        }

        response_.body() = body_stream_.str();
    }

#endif

    // Our last change to change the response before we start sending
    if (this->response_modifier_) {
        (*this->response_modifier_)(response_);
    }

    response_.set(http::field::content_length, response_.body().size());

    /// This attempts to write all data to a stream
    /// TODO: handle the case when we are trying to send too much
    http::async_write(
        stream_, response_, [self = shared_from_this()](error_code ec, size_t) {
            if (ec && ec != boost::asio::error::operation_aborted) {
                LOKI_LOG(error, "Failed to write to a socket: {}",
                         ec.message());
            }

            self->clean_up();
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
        snode["pubkey_x25519"] = sn.pubkey_x25519_hex();
        snode["pubkey_ed25519"] = sn.pubkey_ed25519_hex();
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
            body_stream_ << fmt::format("invalid json: no `{}` field\n", field);
            LOKI_LOG(debug, "Bad client request: no `{}` field", field);
            return;
        }
    }

    const auto ttl = params["ttl"].get<std::string>();
    const auto nonce = params["nonce"].get<std::string>();
    const auto timestamp = params["timestamp"].get<std::string>();
    const auto data = params["data"].get<std::string>();

    bool created;
    auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), created);

    if (!created) {
        response_.result(http::status::bad_request);
        body_stream_ << fmt::format("Pubkey must be {} characters long\n",
                                    get_user_pubkey_size());
        LOKI_LOG(error, "Pubkey must be {} characters long", get_user_pubkey_size());
        return;
    }

    if (data.size() > MAX_MESSAGE_BODY) {
        response_.result(http::status::bad_request);
        body_stream_ << "Message body exceeds maximum allowed length of "
                     << MAX_MESSAGE_BODY << "\n";
        LOKI_LOG(debug, "Message body too long: {}", data.size());
        return;
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        handle_wrong_swarm(pk);
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
        LOKI_LOG(debug, "Forbidden. Invalid TTL: {}", ttl);
        return;
    }
    uint64_t timestampInt;
    if (!util::parseTimestamp(timestamp, ttlInt, timestampInt)) {
        response_.result(http::status::not_acceptable);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << "Timestamp error: check your clock\n";
        LOKI_LOG(debug, "Forbidden. Invalid Timestamp: {}", timestamp);
        return;
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;

    const bool valid_pow =
        checkPoW(nonce, timestamp, ttl, pk.str(), data, messageHash,
                 service_node_.get_curr_pow_difficulty());
#ifndef DISABLE_POW
    if (!valid_pow) {
        response_.result(432); // unassigned http code
        response_.set(http::field::content_type, "application/json");

        json res_body;
        res_body["difficulty"] = service_node_.get_curr_pow_difficulty();
        LOKI_LOG(debug, "Forbidden. Invalid PoW nonce: {}", nonce);

        /// This might throw if not utf-8 endoded
        body_stream_ << res_body.dump();
        return;
    }
#endif

    bool success;

    try {
        const auto msg =
            message_t{pk.str(), data, messageHash, ttlInt, timestampInt, nonce};
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        body_stream_ << e.what() << "\n";
        LOKI_LOG(critical,
                 "Internal Server Error. Could not store message for {}",
                 obfuscate_pubkey(pk.str()));
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
             obfuscate_pubkey(pk.str()));
}

void connection_t::process_snodes_by_pk(const json& params) {

    if (!params.contains("pubKey")) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `pubKey` field\n";
        LOKI_LOG(debug, "Bad client request: no `pubKey` field");
        return;
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);
    if (!success) {
        response_.result(http::status::bad_request);
        body_stream_ << fmt::format("Pubkey must be {} characters long\n",
                                    get_user_pubkey_size());
        LOKI_LOG(debug, "Pubkey must be {} characters long ", get_user_pubkey_size());
        return;
    }

    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pk);
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
        this->body_stream_ << "could not retrieve all entries\n";
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

void connection_t::handle_wrong_swarm(const user_pubkey_t& pubKey) {

    const std::vector<sn_record_t> nodes =
        service_node_.get_snodes_by_pk(pubKey);
    const json res_body = snodes_to_json(nodes);

    response_.result(http::status::misdirected_request);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    body_stream_ << res_body.dump();
    LOKI_LOG(debug, "Client request for different swarm received");
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
        LOKI_LOG(critical,
                 "Internal Server Error. Could not retrieve messages for {}",
                 obfuscate_pubkey(pk));
        return;
    }

    const bool lp_requested = header_.find(LOKI_LONG_POLL_HEADER) != header_.end();

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

    service_node_.all_stats_.bump_retrieve_requests();

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            body_stream_ << fmt::format("invalid json: no `{}` field\n", field);
            LOKI_LOG(debug, "Bad client request: no `{}` field", field);
            return;
        }
    }

    bool success;
    const auto pk =
        user_pubkey_t::create(params["pubKey"].get<std::string>(), success);

    if (!success) {
        response_.result(http::status::bad_request);
        body_stream_ << fmt::format("Pubkey must be {} characters long\n",
                                    get_user_pubkey_size());
        LOKI_LOG(debug, "Pubkey must be {} characters long ", get_user_pubkey_size());
        return;
    }

    if (!service_node_.is_pubkey_for_us(pk)) {
        handle_wrong_swarm(pk);
        return;
    }

    const auto last_hash = params["lastHash"].get<std::string>();

    // we are going to send the response anynchronously
    // once we have new data
    delay_response_ = true;

    poll_db(pk.str(), last_hash);
}


void connection_t::process_client_req(const std::string& req_json) {

    const json body = json::parse(req_json, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json\n";
        LOKI_LOG(debug, "Bad client request: invalid json");
        return;
    }

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `method` field\n";
        LOKI_LOG(debug, "Bad client request: no method field");
        return;
    }

    const auto method_name = method_it->get<std::string>();

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        response_.result(http::status::bad_request);
        body_stream_ << "invalid json: no `params` field\n";
        LOKI_LOG(debug, "Bad client request: no params field");
        return;
    }

    if (method_name == "store") {
        LOKI_LOG(trace, "Process client request: store, connection: {}", this->conn_idx);
        this->process_store(*params_it);
    } else if (method_name == "retrieve") {
        LOKI_LOG(trace, "Process client request: retrieve, connection: {}", this->conn_idx);
        this->process_retrieve(*params_it);
    } else if (method_name == "get_snodes_for_pubkey") {
        LOKI_LOG(trace, "Process client request: snodes for pubkey");
        this->process_snodes_by_pk(*params_it);
    } else {
        response_.result(http::status::bad_request);
        body_stream_ << "no method" << method_name << "\n";
        LOKI_LOG(debug, "Bad client request: unknown method '{}'", method_name);
    }

}

void connection_t::process_client_req_rate_limited() {
    std::string plain_text = request_.body();
    const std::string client_ip =
        socket_.remote_endpoint().address().to_string();
    if (rate_limiter_.should_rate_limit_client(client_ip)) {
        this->body_stream_ << "too many requests\n";
        response_.result(http::status::too_many_requests);
        LOKI_LOG(debug, "Rate limiting client request.");
        return;
    }

#ifndef DISABLE_ENCRYPTION
    // Just in case we ever plan to enable this "channel encryption",
    // this part will probably be broken for proxy requests (wrong
    // place to look for headers)
    if (!parse_header(LOKI_EPHEMKEY_HEADER)) {
        LOKI_LOG(debug, "Bad client request: could not parse headers");
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
        LOKI_LOG(debug, "Bad client request: could not decrypt body");
        return;
    }
#endif

    // Not sure what the original idea was to distinguish between headers
    // in request_ and the actual header_ field, but it is useful for
    // "proxy" client requests as we can have both true html headers
    // and the headers that came encrypted in body
    if (request_.find(LOKI_LONG_POLL_HEADER) != request_.end()) {
        header_[LOKI_LONG_POLL_HEADER] = request_.at(LOKI_LONG_POLL_HEADER).to_string();
    }

    this->process_client_req(plain_text);
}

void connection_t::register_deadline() {

    auto self = shared_from_this();

    // Note: deadline callback captures a shared pointer to this, so
    // the connection will not be destroyed until the timer goes off.
    // If we want to destroy it earlier, we need to manually cancel the timer.
    deadline_.async_wait([self = std::move(self)](error_code ec) {
        const bool cancelled =
            (ec && ec == boost::asio::error::operation_aborted);

        if (cancelled)
            return;

        // Note: cancelled timer does absolutely nothing, so we need to make
        // sure we close the socket (and unsubscribe from notifications)
        // elsewhere if we cancel it.
        if (ec) {
            LOKI_LOG(error, "Deadline timer error [{}]: {}", ec.value(),
                     ec.message());
        }

        LOKI_LOG(debug, "Closing [connection_t] socket due to timeout");
        self->clean_up();
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
    } else if (ec) {
        LOKI_LOG(debug, "Could not close ssl stream gracefully, ec: {} ({})",
                 ec.message(), ec.value());
    }

    const auto sockfd = stream_.lowest_layer().native_handle();
    LOKI_LOG(debug, "Close https socket: {}", sockfd);
    get_net_stats().record_socket_close(sockfd);
    stream_.lowest_layer().close();
}

void connection_t::on_get_stats() {
    this->body_stream_ << service_node_.get_stats();
    this->response_.result(http::status::ok);
}

void connection_t::on_get_logs() {

    /// Limit this call to 1 request per second
    static time_t last_req_time = 0;
    const time_t now = time(nullptr);
    constexpr time_t PERIOD = 1;

    if (now - last_req_time < PERIOD) {
        this->body_stream_ << "Too many request, try again later.";
        this->response_.result(http::status::too_many_requests);
        return;
    }

    last_req_time = now;

    auto dev_sink = dynamic_cast<loki::dev_sink_mt*>(
        spdlog::get("loki_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        LOKI_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        this->body_stream_ << "Developer error: sink #3 is not a dev sink.";
        this->response_.result(http::status::not_implemented);
        return;
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    this->body_stream_ << val.dump(4);
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
      deadline_timer_(ioc), req_(req) {
    get_net_stats().http_connections_out++;
}

void HttpClientSession::on_connect() {

    const auto sockfd = socket_.native_handle();
    LOKI_LOG(debug, "Open http socket: {}", sockfd);
    get_net_stats().record_socket_open(sockfd);
    http::async_write(socket_, *req_,
                      std::bind(&HttpClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpClientSession::on_write(error_code ec, size_t bytes_transferred) {

    LOKI_LOG(trace, "on write");
    if (ec) {
        LOKI_LOG(error, "Http error on write, ec: {}. Message: {}", ec.value(),
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
            // We should make sure that we print the error a few levels above,
            // where we have more context

            if (ec == boost::system::errc::connection_refused) {
                LOKI_LOG(debug,
                         "[http client]: could not connect to {}:{}, message: "
                         "{} ({})",
                         endpoint_.address().to_string(), endpoint_.port(),
                         ec.message(), ec.value());
            } else {
                LOKI_LOG(error,
                         "[http client]: could not connect to {}:{}, message: "
                         "{} ({})",
                         endpoint_.address().to_string(), endpoint_.port(),
                         ec.message(), ec.value());
            }

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
                LOKI_LOG(debug, "client socket timed out");
                self->clean_up();
            }
        });
}

void HttpClientSession::trigger_callback(SNodeError error,
                                         std::shared_ptr<std::string>&& body) {
    LOKI_LOG(trace, "Trigger callback");
    ioc_.post(std::bind(callback_, sn_response_t{error, body, boost::none}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

void HttpClientSession::clean_up() {

    if (!needs_cleanup) {
        // This can happen because the deadline timer
        // triggered and cleaned up the connection already
        LOKI_LOG(debug, "No need for cleanup");
        return;
    }

    needs_cleanup = false;

    if (!socket_.is_open()) {
        /// This should never happen!
        LOKI_LOG(critical, "Socket is already closed");
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

    const auto sockfd = socket_.native_handle();
    socket_.close(ec);

    if (ec) {
        LOKI_LOG(error, "Closing socket {} failed [{}: {}]", sockfd, ec.value(), ec.message());
    } else {
        LOKI_LOG(debug, "Close http socket: {}", sockfd);
        get_net_stats().record_socket_close(sockfd);
    }
}

/// We execute callback (if haven't already) here to make sure it is called
HttpClientSession::~HttpClientSession() {

    if (!used_callback_) {
        // If we destroy the session before posting the callback,
        // it must be due to some error
        ioc_.post(std::bind(callback_,
                            sn_response_t{SNodeError::ERROR_OTHER, nullptr}));
    }

    get_net_stats().http_connections_out--;

    this->clean_up();


}

} // namespace loki
