#pragma once

#include <chrono>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>

#include <nlohmann/json_fwd.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/format.hpp>

#include "oxen_common.h"
#include "oxend_key.h"
#include "oxen_logger.h"
#include "swarm.h"

namespace oxen {

inline constexpr auto SESSION_TIME_LIMIT = 60s;

class RateLimiter;

namespace bhttp = boost::beast::http;
namespace bssl = boost::asio::ssl;

using request_t = bhttp::request<bhttp::string_body>;
using response_t = bhttp::response<bhttp::string_body>;

std::shared_ptr<request_t> build_post_request(
        const ed25519_pubkey& host, const char* target, std::string data);

class Security;

class RequestHandler;
class Response;

enum class SNodeError { NO_ERROR, ERROR_OTHER, NO_REACH, HTTP_ERROR };

struct sn_response_t {
    SNodeError error_code;
    std::shared_ptr<std::string> body;
    std::optional<response_t> raw_response;
};

std::ostream& operator<<(std::ostream& os, const sn_response_t& res);

using http_callback_t = std::function<void(sn_response_t)>;

// Makes an HTTP JSON-RPC request to some oxend; this is currently needed only for bootstrap nodes
// (for a local oxend we speak oxenmq rpc).
void oxend_json_rpc_request(
        boost::asio::io_context& ioc,
        const std::string& daemon_ip,
        const uint16_t daemon_port,
        std::string_view method,
        const nlohmann::json& params,
        http_callback_t&& cb);

void make_http_request(boost::asio::io_context& ioc, const std::string& ip,
                       uint16_t port, std::shared_ptr<request_t> req,
                       http_callback_t&& cb);

class HttpClientSession
    : public std::enable_shared_from_this<HttpClientSession> {

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    tcp::socket socket_;
    tcp::endpoint endpoint_;
    http_callback_t callback_;
    boost::asio::steady_timer deadline_timer_;

    boost::beast::flat_buffer buffer_;
    /// NOTE: this needs to be a shared pointer since
    /// it is very common for the same request to be
    /// sent to multiple snodes
    std::shared_ptr<request_t> req_;
    response_t res_;

    bool used_callback_ = false;
    bool needs_cleanup = true;

    void on_connect();

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void trigger_callback(SNodeError error,
                          std::shared_ptr<std::string>&& body);

    void clean_up();

  public:
    // Resolver and socket require an io_context
    HttpClientSession(boost::asio::io_context& ioc, const tcp::endpoint& ep,
                      const std::shared_ptr<request_t>& req,
                      http_callback_t&& cb);

    // initiate the client connection
    void start();

    ~HttpClientSession();
};

constexpr const char* error_string(SNodeError err) {
    switch (err) {
    case oxen::SNodeError::NO_ERROR:
        return "NO_ERROR";
    case oxen::SNodeError::ERROR_OTHER:
        return "ERROR_OTHER";
    case oxen::SNodeError::NO_REACH:
        return "NO_REACH";
    case oxen::SNodeError::HTTP_ERROR:
        return "HTTP_ERROR";
    default:
        return "[UNKNOWN]";
    }
}

} // namespace oxen

namespace fmt {

template <>
struct formatter<oxen::SNodeError> {

    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const oxen::SNodeError& err, FormatContext& ctx) {
        return format_to(ctx.out(), error_string(err));
    }
};

} // namespace fmt
