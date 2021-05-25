#include "http_connection.h"
#include "Database.hpp"

#include "rate_limiter.h"
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

/// +===========================================

namespace oxen {

using error_code = boost::system::error_code;
using json = nlohmann::json;
using tcp = boost::asio::ip::tcp;

std::ostream& operator<<(std::ostream& os, const sn_response_t& res) {
    switch (res.error_code) {
    case SNodeError::NO_ERROR:
        os << "NO_ERROR";
        break;
    case SNodeError::ERROR_OTHER:
        os << "ERROR_OTHER";
        break;
    case SNodeError::NO_REACH:
        os << "NO_REACH";
        break;
    case SNodeError::HTTP_ERROR:
        os << "HTTP_ERROR";
        break;
    }

    return os << "(" << (res.body ? *res.body : "n/a") << ")";
}

std::shared_ptr<request_t> build_post_request(
        const ed25519_pubkey& host, const char* target, std::string data) {
    auto req = std::make_shared<request_t>();
    req->body() = std::move(data);
    req->method(bhttp::verb::post);
    req->set(bhttp::field::host,
            (host ? oxenmq::to_base32z(host.view()) : "service-node") + ".snode");
    req->target(target);
    req->prepare_payload();
    return req;
}

void make_http_request(boost::asio::io_context& ioc, const std::string& address,
                       uint16_t port, std::shared_ptr<request_t> req,
                       http_callback_t&& cb) {

    auto resolver = std::make_shared<tcp::resolver>(ioc);

    auto resolve_handler = [&ioc, address, port, req=std::move(req), resolver,
                            cb = std::move(cb)](
                               const boost::system::error_code& ec,
                               boost::asio::ip::tcp::resolver::results_type
                                   resolve_results) mutable {
        if (ec) {
            OXEN_LOG(error, "DNS resolution error for {}: {}", address,
                     ec.message());
            return cb({SNodeError::ERROR_OTHER});
        }

        tcp::endpoint endpoint;

        bool resolved = false;

        while (resolve_results != tcp::resolver::iterator()) {
            const tcp::endpoint ep = (resolve_results++)->endpoint();

#ifndef INTEGRATION_TEST
            if (!ep.address().is_v4() || !is_ip_public(ep.address().to_v4())) {
                continue;
            }
#endif
            endpoint = ep;
            resolved = true;
            break;
        }

        if (!resolved) {
            OXEN_LOG(error, "[HTTP] DNS resolution error for {}", address);
            return cb({SNodeError::ERROR_OTHER});
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
    req->method(bhttp::verb::post);
    req->target(target);
    req->prepare_payload();

    OXEN_LOG(trace, "Making oxend request, method: {}", std::string(method));

    make_http_request(ioc, daemon_ip, daemon_port, req, std::move(cb));
}

/// TODO: make generic, avoid message copy
HttpClientSession::HttpClientSession(boost::asio::io_context& ioc,
                                     const tcp::endpoint& ep,
                                     const std::shared_ptr<request_t>& req,
                                     http_callback_t&& cb)
    : ioc_(ioc), socket_(ioc), endpoint_(ep), callback_(cb),
      deadline_timer_(ioc), req_(req) {
}

void HttpClientSession::on_connect() {

    const auto sockfd = socket_.native_handle();
    OXEN_LOG(trace, "Open http socket: {}", sockfd);
    bhttp::async_write(socket_, *req_,
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
    bhttp::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(error_code ec, size_t bytes_transferred) {

    if (!ec || (ec == bhttp::error::end_of_stream)) {

        OXEN_LOG(trace, "Successfully received {} bytes.", bytes_transferred);

        if (bhttp::to_status_class(res_.result_int()) ==
            bhttp::status_class::successful) {
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

    this->clean_up();
}

} // namespace oxen
