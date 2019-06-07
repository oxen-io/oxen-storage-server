#pragma once

#include "http_connection.h"
#include <functional>

namespace loki {
using http_callback_t = std::function<void(sn_response_t)>;

void make_https_request(boost::asio::io_context& ioc, const std::string& ip,
                        uint16_t port, const std::shared_ptr<request_t>& req,
                        http_callback_t&& cb);

class HttpsClientSession
    : public std::enable_shared_from_this<HttpsClientSession> {

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    tcp::resolver::results_type resolve_results_;
    http_callback_t callback_;
    boost::asio::steady_timer deadline_timer_;

    ssl::stream<tcp::socket> stream_;
    boost::beast::flat_buffer buffer_;
    /// NOTE: this needs to be a shared pointer since
    /// it is very common for the same request to be
    /// sent to multiple snodes
    std::shared_ptr<request_t> req_;
    response_t res_;

    bool used_callback_ = false;

    void on_connect();

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void trigger_callback(SNodeError error,
                          std::shared_ptr<std::string>&& body);

    void on_handshake(boost::system::error_code ec);

    void do_close();
    void on_shutdown(boost::system::error_code ec);

  public:
    // Resolver and socket require an io_context
    HttpsClientSession(boost::asio::io_context& ioc, ssl::context& ssl_ctx,
                       tcp::resolver::results_type resolve_results,
                       const std::shared_ptr<request_t>& req,
                       http_callback_t&& cb);

    // initiate the client connection
    void start();

    ~HttpsClientSession();
};
} // namespace loki
