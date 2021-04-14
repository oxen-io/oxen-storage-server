#include "http_connection.h"
#include "Database.hpp"

#include "net_stats.h"
#include "rate_limiter.h"
#include "security.h"
#include "serialization.h"
#include "server_certificates.h"
#include "service_node.h"
#include "signature.h"

// needed for proxy requests
#include "https_client.h"

#include "ip_utils.h"
#include "onion_processing.h"
#include "request_handler.h"

#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <oxenmq/hex.h>
#include <sodium.h>
#include <sstream>
#include <string>
#include <thread>

using json = nlohmann::json;

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>

/// +===========================================

static constexpr auto OXEN_FILE_SERVER_TARGET_HEADER =
    "X-Loki-File-Server-Target";
static constexpr auto OXEN_FILE_SERVER_VERB_HEADER = "X-Loki-File-Server-Verb";
static constexpr auto OXEN_FILE_SERVER_HEADERS_HEADER =
    "X-Loki-File-Server-Headers";

using error_code = boost::system::error_code;

namespace oxen {

constexpr auto TEST_RETRY_PERIOD = std::chrono::milliseconds(50);

std::shared_ptr<request_t> build_post_request(const char* target,
                                              std::string&& data) {
    auto req = std::make_shared<request_t>();
    req->body() = std::move(data);
    req->method(http::verb::post);
    req->set(http::field::host, "service node");
    req->target(target);
    req->prepare_payload();
    return req;
}

void make_http_request(boost::asio::io_context& ioc, const std::string& address,
                       uint16_t port, const std::shared_ptr<request_t>& req,
                       http_callback_t&& cb) {

    auto resolver = std::make_shared<tcp::resolver>(ioc);

    auto resolve_handler = [&ioc, address, port, req, resolver,
                            cb = std::move(cb)](
                               const boost::system::error_code& ec,
                               boost::asio::ip::tcp::resolver::results_type
                                   resolve_results) mutable {
        if (ec) {
            OXEN_LOG(error, "DNS resolution error for {}: {}", address,
                     ec.message());
            cb({SNodeError::ERROR_OTHER});
            return;
        }

        tcp::endpoint endpoint;

        bool resolved = false;

        while (resolve_results != tcp::resolver::iterator()) {
            const tcp::endpoint ep = (resolve_results++)->endpoint();

#ifndef INTEGRATION_TEST
            if (!ep.address().is_v4() || is_ip_public(ep.address().to_v4())) {
                continue;
            }
#endif
            endpoint = ep;
            resolved = true;
            break;
        }

        if (!resolved) {
            OXEN_LOG(error, "[HTTP] DNS resolution error for {}", address);
            cb({SNodeError::ERROR_OTHER});
            return;
        }

        endpoint.port(port);

        auto session = std::make_shared<HttpClientSession>(ioc, endpoint, req,
                                                           std::move(cb));

        session->start();
    };

    resolver->async_resolve(
        address, std::to_string(port),
        boost::asio::ip::tcp::resolver::query::numeric_service,
        resolve_handler);
}

void oxend_json_rpc_request(boost::asio::io_context& ioc,
                            const std::string& daemon_ip,
                            const uint16_t daemon_port, std::string_view method,
                            const nlohmann::json& params,
                            http_callback_t&& cb) {

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

    OXEN_LOG(trace, "Making oxend request, method: {}", std::string(method));

    make_http_request(ioc, daemon_ip, daemon_port, req, std::move(cb));
}

// =============================================================

namespace http_server {

// "Loop" forever accepting new connections.
static void accept_connection(boost::asio::io_context& ioc,
                              boost::asio::ssl::context& ssl_ctx,
                              tcp::acceptor& acceptor, ServiceNode& sn,
                              RequestHandler& rh, RateLimiter& rate_limiter,
                              const Security& security) {

    static boost::asio::steady_timer acceptor_timer(ioc);
    constexpr std::chrono::milliseconds ACCEPT_DELAY = 50ms;

    acceptor.async_accept([&](const error_code& ec, tcp::socket socket) {
        OXEN_LOG(trace, "connection accepted");
        if (!ec) {

            std::make_shared<connection_t>(ioc, ssl_ctx, std::move(socket), sn,
                                           rh, rate_limiter, security)
                ->start();

            accept_connection(ioc, ssl_ctx, acceptor, sn, rh, rate_limiter,
                              security);
        } else {

            // TODO: remove this once we confirmed that there is
            // no more socket leaking
            if (ec == boost::system::errc::too_many_files_open) {
                OXEN_LOG(critical, "Too many open files, aborting");
                abort();
            }

            OXEN_LOG(
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

                accept_connection(ioc, ssl_ctx, acceptor, sn, rh, rate_limiter,
                                  security);
            });
        }
    });
}

void run(boost::asio::io_context& ioc, const std::string& ip, uint16_t port,
         const std::filesystem::path& base_path, ServiceNode& sn,
         RequestHandler& rh, RateLimiter& rate_limiter, Security& security) {

    OXEN_LOG(trace, "http server run");

    const auto address =
        boost::asio::ip::make_address(ip); /// throws if incorrect

    tcp::acceptor acceptor{ioc, {address, port}};

    ssl::context ssl_ctx{ssl::context::tlsv12};

    load_server_certificate(base_path, ssl_ctx);

    security.generate_cert_signature();

    accept_connection(ioc, ssl_ctx, acceptor, sn, rh, rate_limiter, security);

    ioc.run();
}

/// ============ connection_t ============

connection_t::connection_t(boost::asio::io_context& ioc, ssl::context& ssl_ctx,
                           tcp::socket socket, ServiceNode& sn,
                           RequestHandler& rh, RateLimiter& rate_limiter,
                           const Security& security)
    : ioc_(ioc), ssl_ctx_(ssl_ctx), socket_(std::move(socket)),
      stream_(socket_, ssl_ctx_), security_(security), service_node_(sn),
      request_handler_(rh), rate_limiter_(rate_limiter), repeat_timer_(ioc),
      deadline_(ioc, SESSION_TIME_LIMIT), notification_ctx_{std::nullopt} {

    static uint64_t instance_counter = 0;
    conn_idx = instance_counter++;

    get_net_stats().connections_in++;

    OXEN_LOG(trace, "connection_t [{}]", conn_idx);

    request_.body_limit(1024 * 1024 * 10); // 10 mb

    start_timestamp_ = std::chrono::steady_clock::now();
}

connection_t::~connection_t() {

    // Safety net
    if (stream_.lowest_layer().is_open()) {
        OXEN_LOG(debug, "Client socket should be closed by this point, but "
                        "wasn't. Closing now.");
        stream_.lowest_layer().close();
    }

    get_net_stats().connections_in--;

    OXEN_LOG(trace, "~connection_t [{}]", conn_idx);
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
    OXEN_LOG(trace, "Open https socket: {}", sockfd);
    get_net_stats().record_socket_open(sockfd);
    if (ec) {
        OXEN_LOG(debug, "ssl handshake failed: ec: {} ({})", ec.value(),
                 ec.message());
        this->clean_up();
        deadline_.cancel();
        return;
    }

    this->read_request();
}

void connection_t::clean_up() { this->do_close(); }

void connection_t::notify(const message_t* msg) {

    if (!notification_ctx_) {
        OXEN_LOG(error,
                 "Trying to notify a connection without notification context");
        return;
    }

    if (msg) {
        OXEN_LOG(trace, "Processing message notification: {}", msg->data);
        // save messages, so we can access them once the timer event happens
        notification_ctx_->message = *msg;
    }
    // the timer callback will be called once we complete the current callback
    notification_ctx_->timer.cancel();
}

// Asynchronously receive a complete request message.
void connection_t::read_request() {

    auto on_data = [self = shared_from_this()](error_code ec,
                                               size_t bytes_transferred) {
        OXEN_LOG(trace, "on data: {} bytes", bytes_transferred);

        if (ec) {
            OXEN_LOG(
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
            OXEN_LOG(critical, "Exception caught processing a request: {}",
                     e.what());
            self->body_stream_ << e.what();
        }

        if (!self->delay_response_) {
            self->write_response();
        }
    };

    http::async_read(stream_, buffer_, request_, on_data);
}

// Parse a pubkey string value as either base32z (deprecated!), b64, or hex.  Returns a null pk
// (i.e. operator bool() returns false) and warns on invalid input.
static legacy_pubkey parse_pubkey(std::string_view public_key_in) {
    legacy_pubkey pk{};
    if (public_key_in.size() == 64 && oxenmq::is_hex(public_key_in))
        oxenmq::from_hex(public_key_in.begin(), public_key_in.end(), pk.begin());
    else if ((public_key_in.size() == 43 || (public_key_in.size() == 44 && public_key_in.back() == '='))
            && oxenmq::is_base64(public_key_in))
        oxenmq::from_base64(public_key_in.begin(), public_key_in.end(), pk.begin());
    else if (public_key_in.size() == 52 && oxenmq::is_base32z(public_key_in))
        oxenmq::from_base32z(public_key_in.begin(), public_key_in.end(), pk.begin());
    else {
        OXEN_LOG(warn, "Invalid public key header: not hex, b64, or b32z encoded");
        OXEN_LOG(debug, "Received public key encoded value: {}", public_key_in);
    }
    return pk;
}

bool connection_t::validate_snode_request() {
    if (!parse_header(OXEN_SENDER_SNODE_PUBKEY_HEADER,
                      OXEN_SNODE_SIGNATURE_HEADER)) {
        OXEN_LOG(debug, "Missing signature headers for a Service Node request");
        return false;
    }
    const auto& signature_b64 = header_[OXEN_SNODE_SIGNATURE_HEADER];
    legacy_pubkey public_key = parse_pubkey(header_[OXEN_SENDER_SNODE_PUBKEY_HEADER]);
    if (!public_key)
        return false;

    signature sig;
    try {
        sig = signature::from_base64(signature_b64);
    } catch (const std::exception&) {
        OXEN_LOG(warn, "invalid signature (not base64) found in header from {}",
                public_key);
        return false;
    }

    /// Known service node
    auto sn = service_node_.find_node(public_key);
    if (!sn) {
        body_stream_ << "Unknown service node\n";
        OXEN_LOG(debug, "Discarding signature from unknown service node: {}",
                 public_key);
        response_.result(http::status::unauthorized);
        return false;
    }

    if (!check_signature(sig, hash_data(request_.get().body()), public_key)) {
        constexpr auto msg = "Could not verify batch signature"sv;
        OXEN_LOG(debug, "{}", msg);
        body_stream_ << msg;
        response_.result(http::status::unauthorized);
        return false;
    }
    if (rate_limiter_.should_rate_limit(public_key)) {
        this->body_stream_ << "Too many requests\n";
        response_.result(http::status::too_many_requests);
        return false;
    }
    return true;
}

void connection_t::process_storage_test_req(uint64_t height,
                                            const legacy_pubkey& tester_pk,
                                            const std::string& msg_hash) {

    OXEN_LOG(trace, "Performing storage test, attempt: {}", repetition_count_);

    std::string answer;

    /// TODO: we never actually test that `height` is within any reasonable
    /// time window (or that it is not repeated multiple times), we should do
    /// that! This is done implicitly to some degree using
    /// `block_hashes_cache_`, which holds a limited number of recent blocks
    /// only and fails if an earlier block is requested
    const MessageTestStatus status = service_node_.process_storage_test_req(
        height, tester_pk, msg_hash, answer);
    const auto elapsed_time =
        std::chrono::steady_clock::now() - start_timestamp_;
    if (status == MessageTestStatus::SUCCESS) {
        OXEN_LOG(
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
                    OXEN_LOG(error,
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
        // Promote this to `error` once we enforce storage testing
        OXEN_LOG(debug, "Failed storage test, tried {} times.",
                 repetition_count_);
        nlohmann::json json_res;
        json_res["status"] = "other";
        this->body_stream_ << json_res.dump();
        response_.result(http::status::ok);
    }
}

static std::optional<x25519_pubkey> extract_x25519_from_hex(std::string_view hex) {
    try {
        return x25519_pubkey::from_hex(hex);
    } catch (const std::exception& e) {
        OXEN_LOG(warn, "Failed to decode ephemeral key in onion request: {}", e.what());
    }
    return std::nullopt;
}

void connection_t::process_onion_req_v2() {

    OXEN_LOG(debug, "Processing an onion request from client (v2)");

    const request_t& req = this->request_.get();

    // Need to make sure we are not blocking waiting for the response
    delay_response_ = true;

    auto on_response = [wself = std::weak_ptr<connection_t>{
                            shared_from_this()}](oxen::Response res) {
        OXEN_LOG(debug, "Got an onion response as guard node");

        auto self = wself.lock();
        if (!self) {
            OXEN_LOG(debug,
                     "Connection is no longer valid, dropping onion response");
            return;
        }

        self->body_stream_ << res.message();
        self->response_.result(static_cast<int>(res.status()));

        self->write_response();
    };

    try {

        auto res = parse_combined_payload(req.body());

        const json json_req = json::parse(res.json, nullptr, true);
        auto ephem_key = extract_x25519_from_hex(
                json_req.at("ephemeral_key").get_ref<const std::string&>());

        service_node_.record_onion_request();
        request_handler_.process_onion_req(res.ciphertext, *ephem_key,
                                           on_response, true);

    } catch (const std::exception& e) {
        auto msg = fmt::format("Error parsing outer JSON in onion request: {}",
                               e.what());
        OXEN_LOG(error, "{}", msg);
        response_.result(http::status::bad_request);
        this->body_stream_ << std::move(msg);
        this->write_response();
    }
}

void connection_t::process_swarm_req(std::string_view target) {

    const request_t& req = this->request_.get();

    // allow ping request as a quick workaround (and they are cheap)
    if (!validate_snode_request() && (target != "/swarms/ping_test/v1")) {
        return;
    }

    response_.set(OXEN_SNODE_SIGNATURE_HEADER, security_.get_cert_signature());

    if (target == "/swarms/storage_test/v1") {

        /// Set to "bad request" by default
        response_.result(http::status::bad_request);
        OXEN_LOG(trace, "Got storage test request");

        using nlohmann::json;

        const json body = json::parse(req.body(), nullptr, false);

        if (body == nlohmann::detail::value_t::discarded) {
            OXEN_LOG(debug, "Bad snode test request: invalid json");
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
            OXEN_LOG(debug, "Bad snode test request: missing fields in json");
            return;
        }

        const auto it = header_.find(OXEN_SENDER_SNODE_PUBKEY_HEADER);
        if (it == header_.end()) {
            OXEN_LOG(debug, "Ignoring test request, no pubkey present");
            return;
        }
        auto tester_pk = parse_pubkey(it->second);
        if (!tester_pk) {
            OXEN_LOG(debug, "Ignoring test request, invalid pubkey");
            return;
        }
        process_storage_test_req(blk_height, tester_pk, msg_hash);
    } else if (target == "/swarms/ping_test/v1") {
        OXEN_LOG(trace, "Received ping_test");
        service_node_.update_last_ping(false /*not omq*/);
        response_.result(http::status::ok);
    }
}

void connection_t::set_response(const Response& res) {

    response_.result(static_cast<unsigned int>(res.status()));

    std::string content_type;

    switch (res.content_type()) {
    case ContentType::plaintext:
        content_type = "text/plain";
        break;
    case ContentType::json:
        content_type = "application/json";
        break;
    default:
        OXEN_LOG(critical, "Unrecognized content type");
    }

    response_.set(http::field::content_type, content_type);
    body_stream_ << res.message();
}

// Determine what needs to be done with the request message.
void connection_t::process_request() {

    const request_t& req = this->request_.get();

    /// This method is responsible for filling out response_

    OXEN_LOG(debug, "connection_t::process_request");
    response_.version(req.version());
    response_.keep_alive(false);

    /// TODO: make sure that we always send a response!

    response_.result(http::status::internal_server_error);

    const boost::string_view target0 = req.target();
    const std::string_view target =
        std::string_view(target0.data(), target0.size());

    OXEN_LOG(debug, "target: {}", target);

    const bool is_swarm_req = (target.find("/swarms/") == 0);

    if (is_swarm_req) {
        OXEN_LOG(debug, "Processing a swarm request: {}", target);
    }

    switch (req.method()) {
    case http::verb::post: {
        std::string reason;

        // Respond to ping even if we are not ready
        if (target == "/swarms/ping_test/v1") {
            this->process_swarm_req(target);
            break;
        }
        if (!service_node_.snode_ready(&reason)) {
            OXEN_LOG(debug,
                     "Ignoring post request; storage server not ready: {}",
                     reason);
            OXEN_LOG(debug, "Would send 503 error (2)");
            response_.result(http::status::service_unavailable);
            body_stream_ << fmt::format("Service node is not ready: {}\n",
                                        reason);
            break;
        }
        if (target == "/storage_rpc/v1") {
            /// Store/load from clients
            OXEN_LOG(trace, "POST /storage_rpc/v1");

            try {
                process_client_req_rate_limited();
            } catch (std::exception& e) {
                this->body_stream_ << fmt::format(
                    "Exception caught while processing client request: {}",
                    e.what());
                response_.result(http::status::internal_server_error);
                OXEN_LOG(critical,
                         "Exception caught while processing client request: {}",
                         e.what());
            }

        } else if (is_swarm_req) {
            this->process_swarm_req(target);
        } else if (target == "/onion_req/v2") {
            this->process_onion_req_v2();
        }
#ifdef INTEGRATION_TEST
        else if (target == "/retrieve_all") {

            const auto res = request_handler_.process_retrieve_all();
            this->set_response(res);

        } else if (target == "/quit") {
            OXEN_LOG(info, "POST /quit");
            // a bit of a hack: sending response manually
            delay_response_ = true;
            response_.result(http::status::ok);
            write_response();
            ioc_.stop();
        } else if (target == "/sleep") {
            ioc_.post([]() {
                OXEN_LOG(warn, "Sleeping for some time...");
                std::this_thread::sleep_for(std::chrono::seconds(30));
            });
            response_.result(http::status::ok);
        }
#endif
        else {
            OXEN_LOG(debug, "unknown target for POST: {}", target);
            this->body_stream_
                << fmt::format("unknown target for POST: {}", target);
            response_.result(http::status::not_found);
        }
        break;
    }
    case http::verb::get:

        if (target == "/get_stats/v1") {
            this->on_get_stats();
        } else {
            this->body_stream_
                << fmt::format("unknown target for GET: {}", target);
            OXEN_LOG(debug, "unknown target for GET: {}", target);
            response_.result(http::status::not_found);
        }
        break;
    default:
        OXEN_LOG(debug, "bad request");
        response_.result(http::status::bad_request);
        break;
    }
}

// Asynchronously transmit the response message.
void connection_t::write_response() {

    OXEN_LOG(trace, "write response, {} bytes", response_.body().size());

    const std::string body_stream = body_stream_.str();

    if (!body_stream.empty()) {

        if (!response_.body().empty()) {
            OXEN_LOG(debug, "Overwritting non-empty body in response!");
        }

        response_.body() = body_stream_.str();
    }

    // Our last change to change the response before we start sending
    if (this->response_modifier_) {
        this->response_modifier_(response_);
    }

    response_.set(http::field::content_length,
                  std::to_string(response_.body().size()));

    /// This attempts to write all data to a stream
    /// TODO: handle the case when we are trying to send too much
    http::async_write(
        stream_, response_, [self = shared_from_this()](error_code ec, size_t) {
            if (ec && ec != boost::asio::error::operation_aborted) {
                OXEN_LOG(error, "Failed to write to a socket: {}",
                         ec.message());
            }

            self->clean_up();
            /// Is it too early to cancel the deadline here?
            self->deadline_.cancel();
        });
}

bool connection_t::parse_header(const char* key) {
    const auto it = request_.get().find(key);
    if (it == request_.get().end()) {
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

constexpr auto LONG_POLL_TIMEOUT = std::chrono::milliseconds(20000);

/// Move this out of `connection_t` Process client request
/// Decouple responding from http

void connection_t::process_client_req_rate_limited() {

    OXEN_LOG(trace, "process_client_req_rate_limited");

    const request_t& req = this->request_.get();
    std::string plain_text = req.body();
    auto addr = socket_.remote_endpoint().address();
    if (!addr.is_v4()) {
        // We don't (currently?) support IPv6 at all (SS published IPs are only IPv4) so if we
        // somehow get an IPv6 address then it isn't a proper SS request so just drop it.
        response_.result(http::status::bad_request);
        OXEN_LOG(warn, "incoming client request is not IPv4; dropping it");
        return;
    }
    if (rate_limiter_.should_rate_limit_client(addr.to_v4().to_uint())) {
        this->body_stream_ << "too many requests\n";
        response_.result(http::status::too_many_requests);
        OXEN_LOG(debug, "Rate limiting client request.");
        return;
    }

    // Not sure what the original idea was to distinguish between headers
    // in request_ and the actual header_ field, but it is useful for
    // "proxy" client requests as we can have both true html headers
    // and the headers that came encrypted in body
    if (req.find(OXEN_LONG_POLL_HEADER) != req.end()) {
        header_[OXEN_LONG_POLL_HEADER] =
            req.at(OXEN_LONG_POLL_HEADER).to_string();
    }

    const bool lp_requested =
        header_.find(OXEN_LONG_POLL_HEADER) != header_.end();

    // Annoyingly, we might still have old clients that expect long-polling
    // to work, spamming us with "retrieve" requests. The workaround for now
    // is to delay responding to the request for a few seconds

    // Client requests can be asynchronous, so only respond in a callback
    this->delay_response_ = true;

    // TODO: remove this when we remove long-polling from (most) clients
    if (lp_requested) {
        OXEN_LOG(debug, "Received a long-polling request");

        auto delay_timer = std::make_shared<boost::asio::steady_timer>(ioc_);

        delay_timer->expires_after(std::chrono::seconds(2));
        delay_timer->async_wait([self = shared_from_this(), delay_timer,
                                 plaintext = std::move(plain_text)](
                                    const error_code& ec) {
            self->request_handler_.process_client_req(
                plaintext, [wself = std::weak_ptr{self}](
                               oxen::Response res) {
                    auto self = wself.lock();
                    if (!self) {
                        OXEN_LOG(
                            debug,
                            "Connection is no longer valid, dropping response");
                        return;
                    }

                    OXEN_LOG(debug, "Respond to a long-polling client");
                    self->set_response(res);
                    self->write_response();
                });
        });

    } else {
        request_handler_.process_client_req(
            plain_text, [wself = weak_from_this()](oxen::Response res) {
                // // A connection could have been destroyed by the deadline
                // timer
                auto self = wself.lock();
                if (!self) {
                    OXEN_LOG(debug, "Connection is no longer valid, dropping "
                                    "proxy response");
                    return;
                }

                OXEN_LOG(debug, "Respond to a non-long polling client");
                self->set_response(res);
                self->write_response();
            });
    }
}

void connection_t::register_deadline() {

    // Note: deadline callback captures a shared pointer to this, so
    // the connection will not be destroyed until the timer goes off.
    // If we want to destroy it earlier, we need to manually cancel the timer.
    deadline_.async_wait([self = shared_from_this()](error_code ec) {
        const bool cancelled =
            (ec && ec == boost::asio::error::operation_aborted);

        if (cancelled)
            return;

        // Note: cancelled timer does absolutely nothing, so we need to make
        // sure we close the socket (and unsubscribe from notifications)
        // elsewhere if we cancel it.
        if (ec) {
            OXEN_LOG(error, "Deadline timer error [{}]: {}", ec.value(),
                     ec.message());
        }

        OXEN_LOG(debug, "[{}] Closing [connection_t] socket due to timeout",
                 self->conn_idx);
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
        OXEN_LOG(debug, "Could not close ssl stream gracefully, ec: {} ({})",
                 ec.message(), ec.value());
    }

    const auto sockfd = stream_.lowest_layer().native_handle();
    OXEN_LOG(trace, "Close https socket: {}", sockfd);
    get_net_stats().record_socket_close(sockfd);
    stream_.lowest_layer().close();
}

void connection_t::on_get_stats() {
    this->body_stream_ << service_node_.get_stats_for_session_client();
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
    OXEN_LOG(trace, "Open http socket: {}", sockfd);
    get_net_stats().record_socket_open(sockfd);
    http::async_write(socket_, *req_,
                      std::bind(&HttpClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpClientSession::on_write(error_code ec, size_t bytes_transferred) {

    OXEN_LOG(trace, "on write");
    if (ec) {
        OXEN_LOG(error, "Http error on write, ec: {}. Message: {}", ec.value(),
                 ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    OXEN_LOG(trace, "Successfully transferred {} bytes", bytes_transferred);

    // Receive the HTTP response
    http::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(error_code ec, size_t bytes_transferred) {

    if (!ec || (ec == http::error::end_of_stream)) {

        OXEN_LOG(trace, "Successfully received {} bytes.", bytes_transferred);

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {
            std::shared_ptr<std::string> body =
                std::make_shared<std::string>(res_.body());
            trigger_callback(SNodeError::NO_ERROR, std::move(body));
        } else {
            OXEN_LOG(error, "Http request failed, error code: {}",
                     res_.result_int());
            trigger_callback(SNodeError::HTTP_ERROR, nullptr);
        }

    } else {

        if (ec != boost::asio::error::operation_aborted) {
            OXEN_LOG(error, "Error on read: {}. Message: {}", ec.value(),
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
                OXEN_LOG(debug,
                         "[http client]: could not connect to {}:{}, message: "
                         "{} ({})",
                         endpoint_.address().to_string(), endpoint_.port(),
                         ec.message(), ec.value());
            } else {
                OXEN_LOG(error,
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
                    OXEN_LOG(
                        error,
                        "Deadline timer failed in http client session [{}: {}]",
                        ec.value(), ec.message());
                }
            } else {
                OXEN_LOG(debug, "client socket timed out");
                self->clean_up();
            }
        });
}

void HttpClientSession::trigger_callback(SNodeError error,
                                         std::shared_ptr<std::string>&& body) {
    OXEN_LOG(trace, "Trigger callback");
    ioc_.post(std::bind(callback_, sn_response_t{error, body, std::nullopt}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

void HttpClientSession::clean_up() {

    if (!needs_cleanup) {
        // This can happen because the deadline timer
        // triggered and cleaned up the connection already
        OXEN_LOG(debug, "No need for cleanup");
        return;
    }

    needs_cleanup = false;

    if (!socket_.is_open()) {
        /// This should never happen!
        OXEN_LOG(critical, "Socket is already closed");
        return;
    }

    error_code ec;

    /// From boost documentation: "For portable behaviour with respect to
    /// graceful closure of a connected socket, call shutdown() before closing
    /// the socket."
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {
        OXEN_LOG(error, "Socket shutdown failure [{}: {}]", ec.value(),
                 ec.message());
    }

    const auto sockfd = socket_.native_handle();
    socket_.close(ec);

    if (ec) {
        OXEN_LOG(error, "Closing socket {} failed [{}: {}]", sockfd, ec.value(),
                 ec.message());
    } else {
        OXEN_LOG(trace, "Close http socket: {}", sockfd);
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

} // namespace oxen
