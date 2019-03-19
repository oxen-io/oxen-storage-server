#include "Database.hpp"
#include "pow.hpp"
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

#include <boost/log/trivial.hpp>
#include <boost/beast/core/detail/base64.hpp>

#include "http_connection.h"
#include "channel_encryption.hpp"
#include "service_node.h"
#include "Item.hpp"

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>
namespace pt = boost::property_tree; // from <boost/property_tree/>
using namespace service_node;

/// +===========================================

static const std::string LOKI_EPHEMKEY_HEADER = "X-Loki-EphemKey";

using service_node::storage::Item;

namespace loki {

void make_http_request(boost::asio::io_context& ioc, std::string ip,
                       uint16_t port, const request_t& req,
                       http_callback_t cb) {

    boost::system::error_code ec;

    boost::asio::ip::address ip_address =
        boost::asio::ip::address::from_string(ip, ec);

    if (ec) {
        BOOST_LOG_TRIVIAL(error) << "Failed to parse the IP address. Error code = "
                  << ec.value() << ". Message: " << ec.message();
        return;
    }

    boost::asio::ip::tcp::endpoint ep(ip_address, port);

    if (req.target() == "/v1/swarms/push") {
        assert(req.find("X-Loki-recipient") != req.end());
    }

    auto session = std::make_shared<HttpClientSession>(ioc, req, cb);

    session->socket_.async_connect(
        ep, [=](const boost::system::error_code& ec) {
            /// TODO: I think I should just call again if ec == EINTR
            if (ec) {
                BOOST_LOG_TRIVIAL(error) << boost::format("Could not connect to %1%:%2%, message: %3% (%4%)") % ip % port % ec.message() % ec.value();
                /// TODO: handle error better here
                return;
            }

            session->on_connect();
        });
}

void make_http_request(boost::asio::io_context& ioc, std::string ip,
                       uint16_t port, std::string target, std::string body,
                       http_callback_t cb) {

    request_t req;

    req.body() = body;
    req.target(target);

    make_http_request(ioc, ip, port, req, cb);
}

namespace http_server {

using error_code = boost::system::error_code;

static void log_error(const error_code& ec) {
    std::cerr << boost::format("Error(%1%): %2%\n") % ec.value() % ec.message();
}

// "Loop" forever accepting new connections.
static void accept_connection(boost::asio::io_context& ioc,
                              tcp::acceptor& acceptor, tcp::socket& socket,
                              ServiceNode& sn, ChannelEncryption<std::string>& channelEncryption) {

    acceptor.async_accept(socket, [&](const error_code& ec) {

        BOOST_LOG_TRIVIAL(trace) << "connection accepted";
        if (!ec)
            std::make_shared<connection_t>(ioc, std::move(socket), sn, channelEncryption)->start();

        if (ec)
            log_error(ec);

        accept_connection(ioc, acceptor, socket, sn, channelEncryption);
    });
}

void run(boost::asio::io_context& ioc, std::string& ip, uint16_t port,
         ServiceNode& sn, ChannelEncryption<std::string>& channelEncryption) {

    BOOST_LOG_TRIVIAL(trace) << "http server run";

    const auto address =
        boost::asio::ip::make_address(ip); /// throws if incorrect

    boost::asio::ip::tcp::acceptor acceptor{ioc, {address, port}};
    boost::asio::ip::tcp::socket socket{ioc};

    accept_connection(ioc, acceptor, socket, sn, channelEncryption);

    ioc.run();
}

/// ============ connection_t ============

connection_t::connection_t(boost::asio::io_context& ioc, tcp::socket socket,
                           ServiceNode& sn, ChannelEncryption<std::string>& channelEncryption)
    : ioc_(ioc), socket_(std::move(socket)), service_node_(sn),
      channelCipher_(channelEncryption),
      deadline_(ioc, std::chrono::seconds(60)) {

    BOOST_LOG_TRIVIAL(trace) << "connection_t";
    /// NOTE: I'm not sure if the timer is working properly
}

connection_t::~connection_t() {
    BOOST_LOG_TRIVIAL(trace) << "~connection_t";
}

void connection_t::start() {
    register_deadline();
    read_request();
}

// Asynchronously receive a complete request message.
void connection_t::read_request() {

    auto self = shared_from_this();

    auto on_data = [self](error_code ec, size_t bytes_transferred) {

        BOOST_LOG_TRIVIAL(trace) << "on data";

        boost::ignore_unused(bytes_transferred);

        if (ec) {
            log_error(ec);
            return;
        }

        // NOTE: this is blocking, we should make this asyncronous
        try {
            self->process_request();
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "Exception caught: " << e.what();
        }

        self->write_response();

    };

    http::async_read(socket_, buffer_, request_, on_data);


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
                BOOST_LOG_TRIVIAL(trace) << "exception caught while processing client request: " << e.what();
            }

        /// Make sure only service nodes can use this API
        } else if (target == "/v1/swarms/push") {

            BOOST_LOG_TRIVIAL(trace) << "swarms/push";

            const std::vector<std::string> keys = {"X-Loki-recipient"};

            parse_header(keys);

            BOOST_LOG_TRIVIAL(trace) << "got PK: " << header_["X-Loki-recipient"];

            std::string text = request_.body();

            auto pk = header_["X-Loki-recipient"];

            // TODO: Actually use the message values here
            auto msg = std::make_shared<message_t>(pk.c_str(), text.c_str(), "", 0);

            /// TODO: this will need to be done asyncronoulsy
            service_node_.process_push(msg);

            response_.result(http::status::ok);
        } else if (target == "/retrieve_all") {
            bodyStream_ << service_node_.get_all_messages();
            response_.result(http::status::ok);
        } else if (target == "/v1/swarms/push_all") {
            response_.result(http::status::ok);

            std::string body = request_.body();

            // TODO: investigate whether I need a string here
            service_node_.process_push_all(std::make_shared<std::string>(body));

        } else if (target == "/test") {
            // response_.body() = "all good!";
            response_.result(http::status::ok);
            bodyStream_ << "All good!";
        } else if (target == "/quit") {
            BOOST_LOG_TRIVIAL(trace) << "got /quit request";
            ioc_.stop();
            // exit(0);
        } else if (target == "/purge") {
            BOOST_LOG_TRIVIAL(trace) << "got /purge request";
            service_node_.purge_outdated();
        } else {
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

// Asynchronously transmit the response message.
void connection_t::write_response() {

    std::string body = bodyStream_.str();

    const auto it = header_.find(LOKI_EPHEMKEY_HEADER);
    if (it != header_.end()) {
        const std::string& ephemKey = it->second;
        try {
            body = channelCipher_.encrypt(body, ephemKey);
            body = boost::beast::detail::base64_encode(body);
            response_.set(http::field::content_type, "text/plain");
        } catch (const std::exception& e) {
            response_.result(http::status::internal_server_error);
            response_.set(http::field::content_type, "text/plain");
            body = "Could not encrypt/encode response: ";
            body += e.what();
            BOOST_LOG_TRIVIAL(error)
                << "Internal Server Error. Could not encrypt response for "
                << ephemKey.substr(0, 2) << "..."
                << ephemKey.substr(ephemKey.length() - 3,
                                    ephemKey.length() - 1);
        }
    }

    response_.body() = body;
    response_.set(http::field::content_length, response_.body().size());

    auto self = shared_from_this();

    /// This attempts to write all data to a stream
    /// TODO: handle the case when we are trying to send too much
    http::async_write(socket_, response_, [self](error_code ec, size_t) {
        self->socket_.shutdown(tcp::socket::shutdown_send, ec);
        self->deadline_.cancel();
    });
}

template <typename T> bool connection_t::parse_header(T key_list) {
    for (const auto key : key_list) {
        const auto it = request_.find(key);
        if (it == request_.end()) {
            response_.result(http::status::bad_request);
            response_.set(http::field::content_type, "text/plain");
            bodyStream_ << "Missing field in header : " << key;

            BOOST_LOG_TRIVIAL(error) << "Missing field in header : " << key;
            return false;
        }
        header_[key] = it->value().to_string();
    }
    return true;
}

void connection_t::process_store(const pt::ptree& params) {
    const auto pubKey = params.get<std::string>("pubKey");
    const auto ttl = params.get<std::string>("ttl");
    const auto nonce = params.get<std::string>("nonce");
    const auto timestamp = params.get<std::string>("timestamp");
    const auto data = params.get<std::string>("data");

    BOOST_LOG_TRIVIAL(trace) << "store body: " << data;

    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt)) {
        response_.result(http::status::forbidden);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << "Provided TTL is not valid.";
        BOOST_LOG_TRIVIAL(error) << "Forbidden. Invalid TTL " << ttl;
        return;
    }

    // Do not store message if the PoW provided is invalid
    std::string messageHash;
    const bool validPoW =
        checkPoW(nonce, timestamp, ttl, pubKey, data, messageHash);
    if (!validPoW) {
        response_.result(http::status::forbidden);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << "Provided PoW nonce is not valid.";
        BOOST_LOG_TRIVIAL(error)
            << "Forbidden. Invalid PoW nonce " << nonce;
        return;
    }

    bool success;

    try {
        auto msg = std::make_shared<message_t>(pubKey.c_str(), data.c_str(), messageHash.c_str(), ttlInt);
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << e.what();
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not store message for "
            << pubKey.substr(0, 2) << "..."
            << pubKey.substr(pubKey.length() - 3,
                                pubKey.length() - 1);
        return;
    }

    if (!success) {
        response_.result(http::status::conflict);
        response_.set(http::field::content_type, "text/plain");
        // TODO: Maybe this shouldn't respond with error
        bodyStream_ << "hash conflict - resource already present.";
        BOOST_LOG_TRIVIAL(warning) << "Conflict. Message with hash "
                                    << messageHash << " already present";
        return;
    }

    response_.result(http::status::ok);
    BOOST_LOG_TRIVIAL(trace)
        << "Successfully stored message for " << pubKey.substr(0, 2)
        << "..."
        << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
}

void connection_t::process_retrieve(const pt::ptree& params) {
    const auto pubKey = params.get<std::string>("pubKey");
    const auto last_hash = params.get("lastHash", "");

    std::vector<Item> items;

    if(!service_node_.retrieve(pubKey, last_hash, items)) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not retrieve messages for "
            << pubKey.substr(0, 2) << "..."
            << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
        return;
    }

    pt::ptree root;
    pt::ptree messagesNode;

    for (const auto& item : items) {
        pt::ptree messageNode;
        messageNode.put("hash", item.hash);
        messageNode.put("expiration", item.expirationTimestamp);
        messageNode.put("data", item.bytes);
        messagesNode.push_back(std::make_pair("", messageNode));
    }
    if (messagesNode.size() != 0) {
        root.add_child("messages", messagesNode);
        root.put("lastHash", items.back().hash);
        BOOST_LOG_TRIVIAL(trace)
            << "Successfully retrieved messages for " << pubKey.substr(0, 2)
            << "..."
            << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
    }
    std::ostringstream buf;
    pt::write_json(buf, root);
    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");
    bodyStream_ << buf.str();
}

void connection_t::process_client_req() {

    const std::vector<std::string> keys = {LOKI_EPHEMKEY_HEADER};
    if (!parse_header(keys)) {
        BOOST_LOG_TRIVIAL(error) << "Could not parse headers\n";
        return;
    }
    std::string plainText = request_.body();

    try {
        const std::string decoded =
            boost::beast::detail::base64_decode(plainText);
        plainText =
            channelCipher_.decrypt(decoded, header_[LOKI_EPHEMKEY_HEADER]);
    } catch (const std::exception& e) {
        response_.result(http::status::bad_request);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << "Could not decode/decrypt body: ";
        bodyStream_ << e.what();
        BOOST_LOG_TRIVIAL(error) << "Bad Request. Could not decrypt body";
    }

    // parse json
    pt::ptree root;
    std::stringstream ss;
    ss << plainText;

    /// TODO: this may throw, need to handle
    pt::json_parser::read_json(ss, root);

    const auto method_name = root.get("method", "");

    if (method_name == "store") {
        process_store(root.get_child("params"));
    } else if (method_name == "retrieve") {
        process_retrieve(root.get_child("params"));
    } else {
        response_.result(http::status::bad_request);
        bodyStream_ << "no method" << method_name;
        BOOST_LOG_TRIVIAL(error)
            << "Bad Request. Unknown method '" << method_name << "'";
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
                                     const request_t& req, http_callback_t cb)
    : ioc_(ioc), socket_(ioc), callback_(cb) {

    if (req.target() == "/v1/swarms/push") {
        assert(req.find("X-Loki-recipient") != req.end());

        req_.set("X-Loki-recipient", req.at("X-Loki-recipient"));
    }

    req_.method(http::verb::post);
    req_.version(11);
    req_.target(req.target());
    req_.set(http::field::host, "localhost");
    req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req_.body() = req.body();
    req_.prepare_payload();
}

void HttpClientSession::on_connect() {

    BOOST_LOG_TRIVIAL(trace) << "on connect";
    http::async_write(socket_, req_,
                      std::bind(&HttpClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpClientSession::on_write(boost::system::error_code ec,
                                 std::size_t bytes_transferred) {

    BOOST_LOG_TRIVIAL(trace) << "on write";
    if (ec) {
        BOOST_LOG_TRIVIAL(error) << "Error on write, ec: " << ec.value()
                  << ". Message: " << ec.message();
        return;
    }

    BOOST_LOG_TRIVIAL(trace) << "Successfully transferred " << bytes_transferred << " bytes";

    // Receive the HTTP response
    http::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(boost::system::error_code ec,
                                std::size_t bytes_transferred) {

    BOOST_LOG_TRIVIAL(trace) << "Successfully received " << bytes_transferred << " bytes";

    std::shared_ptr<std::string> body = nullptr;

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(res_.result_int()) == http::status_class::successful) {
            body = std::make_shared<std::string>(res_.body());
        }

    } else {
        BOOST_LOG_TRIVIAL(error) << "Error on read: " << ec.value()
            << ". Message: " << ec.message();
    }

    // Gracefully close the socket
    socket_.shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        BOOST_LOG_TRIVIAL(error) << "ec: " << ec.value() << ". Message: " << ec.message();
        return;
    }

    init_callback(body);

    // If we get here then the connection is closed gracefully
}

void HttpClientSession::init_callback(std::shared_ptr<std::string> body) {

    ioc_.post(std::bind(callback_, body));
    used_callback_ = true;
}

/// We execute callback (if haven't already) here to make sure it is called
HttpClientSession::~HttpClientSession() {

    if (!used_callback_) {
        ioc_.post(std::bind(callback_, nullptr));
    }
}

} // namespace loki
