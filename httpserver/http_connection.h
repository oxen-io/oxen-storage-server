#pragma once

#include <iostream>
#include <map>
#include <memory>

#include "../external/json.hpp"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/format.hpp>

template <typename T>
class ChannelEncryption;

namespace loki {
class ServiceNode;
}

namespace http = boost::beast::http; // from <boost/beast/http.hpp>

using request_t = http::request<http::string_body>;

using http_callback_t = std::function<void(std::shared_ptr<std::string>)>;

namespace loki {

void make_http_request(boost::asio::io_context& ioc, std::string ip,
                       uint16_t port, const request_t& req, http_callback_t cb);

void make_http_request(boost::asio::io_context& ioc, std::string ip,
                       uint16_t port, std::string target, std::string body,
                       http_callback_t cb);

class HttpClientSession
    : public std::enable_shared_from_this<HttpClientSession> {

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    boost::beast::flat_buffer buffer_;
    request_t req_;
    http::response<http::string_body> res_;

    http_callback_t callback_;

    bool used_callback_ = false;

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void init_callback(std::shared_ptr<std::string> body);

  public:
    tcp::socket socket_;
    // Resolver and socket require an io_context
    explicit HttpClientSession(boost::asio::io_context& ioc,
                               const request_t& req, http_callback_t cb);

    void on_connect();

    ~HttpClientSession();
};

namespace http_server {

class connection_t : public std::enable_shared_from_this<connection_t> {

    using tcp = boost::asio::ip::tcp;

  private:
    boost::asio::io_context& ioc_;

    // The socket for the currently connected client.
    tcp::socket socket_;

    // The buffer for performing reads.
    boost::beast::flat_buffer buffer_{8192};

    // The request message.
    http::request<http::string_body> request_;

    // The response message.
    http::response<http::string_body> response_;

    /// TODO: move these if possible
    std::map<std::string, std::string> header_;

    // The timer for putting a deadline on connection processing.
    boost::asio::basic_waitable_timer<std::chrono::steady_clock> deadline_;

    ServiceNode& service_node_;

    ChannelEncryption<std::string>& channelCipher_;

    std::stringstream bodyStream_;

  public:
    connection_t(boost::asio::io_context& ioc, tcp::socket socket,
                 ServiceNode& sn,
                 ChannelEncryption<std::string>& channelEncryption);

    ~connection_t();

    /// Initiate the asynchronous operations associated with the connection.
    void start();

  private:
    /// Asynchronously receive a complete request message.
    void read_request();

    /// Determine what needs to be done with the request message
    /// (synchronously).
    void process_request();

    void process_store(const nlohmann::json& params);

    void process_retrieve(const nlohmann::json& params);

    void process_snodes_by_pk(const nlohmann::json& params);

    void process_retrieve_all();

    /// Asynchronously transmit the response message.
    void write_response();

    /// Syncronously (?) process client store/load requests
    void process_client_req();

    // Check whether we have spent enough time on this connection.
    void register_deadline();

    /// TODO: should move somewhere else
    template <typename T>
    bool parse_header(T key_list);
};

void run(boost::asio::io_context& ioc, std::string& ip, uint16_t port,
         ServiceNode& sn, ChannelEncryption<std::string>& channelEncryption);

} // namespace http_server

} // namespace loki
