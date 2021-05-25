#pragma once

#include "http_connection.h"
#include <functional>
#include <optional>

namespace oxen {
using http_callback_t = std::function<void(sn_response_t)>;

void make_https_request_to_sn(boost::asio::io_context& ioc,
                              const sn_record_t& sn,
                              std::shared_ptr<request_t> req,
                              http_callback_t&& cb);

void make_https_request(boost::asio::io_context& ioc, const std::string& url,
                        uint16_t port, std::shared_ptr<request_t> req,
                        http_callback_t&& cb);

class HttpsClientSession
    : public std::enable_shared_from_this<HttpsClientSession> {

    // For debugging purposes mostly
    uint64_t connection_idx;

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    bssl::context& ssl_ctx_;
    tcp::resolver::results_type resolve_results_;
    http_callback_t callback_;
    boost::asio::steady_timer deadline_timer_;

    // keep the cert in memory for post-handshake verification
    std::string server_cert_;

    bssl::stream<tcp::socket> stream_;
    boost::beast::flat_buffer buffer_;
    /// NOTE: this needs to be a shared pointer since
    /// it is very common for the same request to be
    /// sent to multiple snodes
    std::shared_ptr<request_t> req_;

    bhttp::response_parser<bhttp::string_body> response_;

    // Snode's pub key (none if signature verification is not used / not a
    // snode)
    std::optional<legacy_pubkey> server_pubkey_;

    bool used_callback_ = false;

    void on_connect();

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void
    trigger_callback(SNodeError error, std::shared_ptr<std::string>&& body,
                     std::optional<response_t> raw_response = std::nullopt);

    void on_handshake(boost::system::error_code ec);
    bool verify_signature();

    void do_close();
    void on_shutdown(boost::system::error_code ec);

  public:
    // Resolver and socket require an io_context
    HttpsClientSession(boost::asio::io_context& ioc, bssl::context& ssl_ctx,
                       tcp::resolver::results_type resolve_results,
                       const char* host, std::shared_ptr<request_t> req,
                       http_callback_t&& cb,
                       std::optional<legacy_pubkey> sn_pubkey);

    // initiate the client connection
    void start();

    ~HttpsClientSession();
};
} // namespace oxen
