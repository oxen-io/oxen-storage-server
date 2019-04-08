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

#include <boost/beast/core/detail/base64.hpp>
#include <boost/log/trivial.hpp>

#include "Item.hpp"
#include "channel_encryption.hpp"
#include "http_connection.h"
#include "service_node.h"

#include "serialization.h"

using json = nlohmann::json;

using tcp = boost::asio::ip::tcp;    // from <boost/asio.hpp>
namespace http = boost::beast::http; // from <boost/beast/http.hpp>
using namespace service_node;

/// +===========================================

static const std::string LOKI_EPHEMKEY_HEADER = "X-Loki-EphemKey";

using service_node::storage::Item;

namespace loki {

void make_http_request(boost::asio::io_context& ioc, std::string sn_address,
                       uint16_t port, const request_t& req,
                       http_callback_t cb) {

    boost::system::error_code ec;

    boost::asio::ip::tcp::endpoint endpoint;
    boost::asio::ip::tcp::resolver resolver(ioc);
    boost::asio::ip::tcp::resolver::iterator destination =
        resolver.resolve(sn_address, "http", ec);
    if (ec) {
        BOOST_LOG_TRIVIAL(error)
            << "Failed to parse the IP address. Error code = " << ec.value()
            << ". Message: " << ec.message();
        return;
    }
    while (destination != boost::asio::ip::tcp::resolver::iterator()) {
        endpoint = *destination++;
    }
    endpoint.port(port);

    auto session = std::make_shared<HttpClientSession>(ioc, req, cb);

    session->socket_.async_connect(
        endpoint, [=](const boost::system::error_code& ec) {
            /// TODO: I think I should just call again if ec == EINTR
            if (ec) {
                BOOST_LOG_TRIVIAL(error)
                    << boost::format(
                           "Could not connect to %1%:%2%, message: %3% (%4%)") %
                           sn_address % port % ec.message() % ec.value();
                /// TODO: handle error better here
                return;
            }

            session->on_connect();
        });
}

void make_http_request(boost::asio::io_context& ioc, std::string sn_address,
                       uint16_t port, std::string target, std::string body,
                       http_callback_t cb) {

    request_t req;

    req.body() = body;
    req.target(target);

    make_http_request(ioc, sn_address, port, req, cb);
}

static void parse_swarm_update(const std::shared_ptr<std::string>& response_body, const swarm_callback_t&& cb) {
    const json body = json::parse(*response_body, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        BOOST_LOG_TRIVIAL(error) << "Bad lokid rpc response: invalid json";
        return;
    }
    all_swarms_t all_swarms;
    std::map<swarm_id_t, std::vector<sn_record_t>> swarm_map;

    try {
        const json service_node_states_string = body["result"]["as_json"];
        const std::string list_string = service_node_states_string.get<std::string>();
        const json service_node_states = json::parse(list_string, nullptr, false);

        for(const auto &sn_json : service_node_states) {
            const std::string pubkey = sn_json["pubkey"].get<std::string>();
            const swarm_id_t swarm_id = sn_json["info"]["swarm_id"].get<swarm_id_t>();
#ifndef INTEGRATION_TEST
            std::string snode_address = util::hex64_to_base32z(pubkey);
            snode_address.append(".snode");
            const sn_record_t sn{
                SNODE_PORT,
                snode_address
            };
#else
            const sn_record_t sn{
                static_cast<uint16_t>(stoi(pubkey)),
                "0.0.0.0"
            };
#endif

            swarm_map[swarm_id].push_back(sn);
        }
    } catch (...) {
        BOOST_LOG_TRIVIAL(error) << "Bad lokid rpc response: invalid json";
        return;
    }

    for(auto const &swarm : swarm_map) {
        all_swarms.emplace_back(SwarmInfo{
            swarm.first,
            swarm.second
        });
    }

    try {
        cb(all_swarms);
    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error)
            << "Exception caught on swarm update: "
            << e.what();
    }
}

void request_swarm_update(boost::asio::io_context& ioc, const swarm_callback_t&& cb) {
    BOOST_LOG_TRIVIAL(trace) << "UPDATING SWARMS: begin";

    const std::string ip = "127.0.0.1";
    const uint16_t port = 38157;
    const std::string target = "/json_rpc";
    const std::string req_body =
        R"#({
            "jsonrpc":"2.0",
            "id":"0",
            "method":"get_service_nodes",
            "params": {
                "sevice_node_pubkeys": [],
                "include_json": true
            }
        })#";

    make_http_request(
        ioc, ip, port, target, req_body,
        [cb = std::move(cb)](const std::shared_ptr<std::string>& result_body) {
            if (result_body) {
                parse_swarm_update(result_body, std::move(cb));
            }
        }
    );
}

namespace http_server {

using error_code = boost::system::error_code;

static void log_error(const error_code& ec) {
    std::cerr << boost::format("Error(%1%): %2%\n") % ec.value() % ec.message();
}

// "Loop" forever accepting new connections.
static void
accept_connection(boost::asio::io_context& ioc, tcp::acceptor& acceptor,
                  tcp::socket& socket, ServiceNode& sn,
                  ChannelEncryption<std::string>& channelEncryption) {

    acceptor.async_accept(socket, [&](const error_code& ec) {
        BOOST_LOG_TRIVIAL(trace) << "connection accepted";
        if (!ec)
            std::make_shared<connection_t>(ioc, std::move(socket), sn,
                                           channelEncryption)
                ->start();

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
                           ServiceNode& sn,
                           ChannelEncryption<std::string>& channelEncryption)
    : ioc_(ioc), socket_(std::move(socket)), service_node_(sn),
      channelCipher_(channelEncryption),
      deadline_(ioc, std::chrono::seconds(60)) {

    BOOST_LOG_TRIVIAL(trace) << "connection_t";
    /// NOTE: I'm not sure if the timer is working properly
}

connection_t::~connection_t() { BOOST_LOG_TRIVIAL(trace) << "~connection_t"; }

void connection_t::start() {
    register_deadline();
    read_request();
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
                BOOST_LOG_TRIVIAL(error)
                    << "exception caught while processing client request: "
                    << e.what();
            }

            /// Make sure only service nodes can use this API
        } else if (target == "/v1/swarms/push") {

            BOOST_LOG_TRIVIAL(trace) << "swarms/push";

            /// NOTE:: we only expect one message here, but
            /// for now lets reuse the function we already have
            std::vector<message_t> messages =
                deserialize_messages(request_.body());
            assert(messages.size() == 1);

            auto msg = std::make_shared<message_t>(messages[0]);

            BOOST_LOG_TRIVIAL(trace) << "got PK: " << msg->pub_key;

            /// TODO: this will need to be done asynchronoulsy
            service_node_.process_push(msg);

            response_.result(http::status::ok);
        } else if (target == "/retrieve_all") {
            process_retrieve_all();
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

#ifndef DISABLE_ENCRYPTION
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
#endif

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

template <typename T>
bool connection_t::parse_header(T key_list) {
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

void connection_t::process_store(const json& params) {

    constexpr const char* fields[] = {"pubKey", "ttl", "nonce", "timestamp", "data"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            bodyStream_ << boost::format("invalid json: no `%1%` field") %
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
        bodyStream_ << "Pubkey must be 66 characters long";
        BOOST_LOG_TRIVIAL(error) << "Pubkey must be 66 characters long ";
        return;
    }

    if (!service_node_.is_pubkey_for_us(pubKey)) {
        handle_wrong_swarm(pubKey);
        return;
    }

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
#ifndef DISABLE_POW
    if (!validPoW) {
        response_.result(http::status::forbidden);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << "Provided PoW nonce is not valid.";
        BOOST_LOG_TRIVIAL(error) << "Forbidden. Invalid PoW nonce " << nonce;
        return;
    }
#endif

    bool success;

    try {

        auto ts = std::stoull(timestamp);
        auto msg = std::make_shared<message_t>(pubKey, data, messageHash,
                                               ttlInt, ts, nonce);
        success = service_node_.process_store(msg);
    } catch (std::exception e) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << e.what();
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not store message for "
            << pubKey.substr(0, 2) << "..."
            << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
        return;
    }

    if (!success) {
        response_.result(http::status::service_unavailable);
        response_.set(http::field::content_type, "text/plain");
        bodyStream_ << "Service node is initializing";
        BOOST_LOG_TRIVIAL(warning) << "Service node is initializing";
        return;
    }

    response_.result(http::status::ok);
    BOOST_LOG_TRIVIAL(trace)
        << "Successfully stored message for " << pubKey.substr(0, 2) << "..."
        << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
}

void connection_t::process_snodes_by_pk(const json& params) {

    if (!params.contains("pubKey")) {
        response_.result(http::status::bad_request);
        bodyStream_ << "invalid json: no `pubKey` field";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: no `pubKey` field";
        return;
    }

    auto pubKey = params["pubKey"].get<std::string>();

    if (pubKey.size() != 66) {
        response_.result(http::status::bad_request);
        bodyStream_ << "Pubkey must be 66 characters long";
        BOOST_LOG_TRIVIAL(error) << "Pubkey must be 66 characters long ";
        return;
    }

    std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pubKey);

    json res_body;

    json snodes = json::array();

    for (const auto& sn : nodes) {
#ifdef INTEGRATION_TEST
        snodes.push_back(std::to_string(sn.port));
#else
        snodes.push_back(sn.address);
#endif
    }

    res_body["snodes"] = snodes;

    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    bodyStream_ << res_body.dump();
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

    bodyStream_ << res_body.dump();
    response_.result(http::status::ok);
}

void connection_t::handle_wrong_swarm(const std::string& pubKey) {
    const std::vector<sn_record_t> nodes = service_node_.get_snodes_by_pk(pubKey);

    json res_body;
    json snodes = json::array();

    for (const auto& sn : nodes) {
#ifdef INTEGRATION_TEST
        snodes.push_back(std::to_string(sn.port));
#else
        snodes.push_back(sn.address);
#endif
    }

    res_body["snodes"] = snodes;

    response_.result(http::status::misdirected_request);
    response_.set(http::field::content_type, "application/json");

    /// This might throw if not utf-8 endoded
    bodyStream_ << res_body.dump();
    BOOST_LOG_TRIVIAL(info) << "Client request for different swarm received";
}

void connection_t::process_retrieve(const json& params) {

    constexpr const char* fields[] = {"pubKey", "lastHash"};

    for (const auto& field : fields) {
        if (!params.contains(field)) {
            response_.result(http::status::bad_request);
            bodyStream_ << boost::format("invalid json: no `%1%` field") %
                               field;
            BOOST_LOG_TRIVIAL(error)
                << boost::format("Bad client request: no `%1%` field") % field;
            return;
        }
    }

    const auto pubKey = params["pubKey"].get<std::string>();
    const auto last_hash = params["lastHash"].get<std::string>();

    if (!service_node_.is_pubkey_for_us(pubKey)) {
        handle_wrong_swarm(pubKey);
        return;
    }

    std::vector<Item> items;

    if (!service_node_.retrieve(pubKey, last_hash, items)) {
        response_.result(http::status::internal_server_error);
        response_.set(http::field::content_type, "text/plain");
        BOOST_LOG_TRIVIAL(error)
            << "Internal Server Error. Could not retrieve messages for "
            << pubKey.substr(0, 2) << "..."
            << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
        return;
    }

    json res_body;
    json messages = json::array();

    for (const auto& item : items) {
        json message;
        message["hash"] = item.hash;
        message["expiration"] = item.expiration_timestamp;
        message["data"] = item.data;
        messages.push_back(message);
    }

    res_body["messages"] = messages;

    if (!items.empty()) {
        BOOST_LOG_TRIVIAL(trace)
            << "Successfully retrieved messages for " << pubKey.substr(0, 2)
            << "..." << pubKey.substr(pubKey.length() - 3, pubKey.length() - 1);
    }

    response_.result(http::status::ok);
    response_.set(http::field::content_type, "application/json");
    bodyStream_ << res_body.dump();
}

void connection_t::process_client_req() {
    std::string plainText = request_.body();

#ifndef DISABLE_ENCRYPTION
    const std::vector<std::string> keys = {LOKI_EPHEMKEY_HEADER};
    if (!parse_header(keys)) {
        BOOST_LOG_TRIVIAL(error) << "Could not parse headers\n";
        return;
    }

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
        return;
    }
#endif

    json body = json::parse(plainText, nullptr, false);
    if (body == nlohmann::detail::value_t::discarded) {
        response_.result(http::status::bad_request);
        bodyStream_ << "invalid json";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: invalid json";
        return;
    }

    const auto method_it = body.find("method");
    if (method_it == body.end() || !method_it->is_string()) {
        response_.result(http::status::bad_request);
        bodyStream_ << "invalid json: no `method` field";
        BOOST_LOG_TRIVIAL(error) << "Bad client request: no method field";
        return;
    }

    const auto method_name = method_it->get<std::string>();

    const auto params_it = body.find("params");
    if (params_it == body.end() || !params_it->is_object()) {
        response_.result(http::status::bad_request);
        bodyStream_ << "invalid json: no `params` field";
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
        bodyStream_ << "no method" << method_name;
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
                                     const request_t& req, http_callback_t cb)
    : ioc_(ioc), socket_(ioc), callback_(cb) {

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

    BOOST_LOG_TRIVIAL(trace)
        << "Successfully transferred " << bytes_transferred << " bytes";

    // Receive the HTTP response
    http::async_read(socket_, buffer_, res_,
                     std::bind(&HttpClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpClientSession::on_read(boost::system::error_code ec,
                                std::size_t bytes_transferred) {

    BOOST_LOG_TRIVIAL(trace)
        << "Successfully received " << bytes_transferred << " bytes";

    std::shared_ptr<std::string> body = nullptr;

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {
            body = std::make_shared<std::string>(res_.body());
        }

    } else {
        BOOST_LOG_TRIVIAL(error)
            << "Error on read: " << ec.value() << ". Message: " << ec.message();
    }

    // Gracefully close the socket
    socket_.shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        BOOST_LOG_TRIVIAL(error)
            << "ec: " << ec.value() << ". Message: " << ec.message();
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
