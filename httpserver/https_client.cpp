#include "https_client.h"

#include <boost/log/trivial.hpp>

namespace loki {

using error_code = boost::system::error_code;

void make_https_request(boost::asio::io_context& ioc,
                        const std::string& sn_address, uint16_t port,
                        const std::shared_ptr<request_t>& req,
                        http_callback_t&& cb) {

    error_code ec;
    boost::asio::ip::tcp::resolver resolver(ioc);
#ifdef INTEGRATION_TEST
    const auto resolve_results =
        resolver.resolve("0.0.0.0", std::to_string(port), ec);
#else
    const auto resolve_results =
        resolver.resolve(sn_address, std::to_string(port), ec);
#endif
    if (ec) {
        LOG(error) << "https: Failed to parse the IP address. Error code = "
                   << ec.value() << ". Message: " << ec.message();
        return;
    }

    static ssl::context ctx{ssl::context::tlsv12_client};

    auto session = std::make_shared<HttpsClientSession>(
        ioc, ctx, std::move(resolve_results), req, std::move(cb));

    session->start();
}

HttpsClientSession::HttpsClientSession(
    boost::asio::io_context& ioc, ssl::context& ssl_ctx,
    tcp::resolver::results_type resolve_results,
    const std::shared_ptr<request_t>& req, http_callback_t&& cb)
    : ioc_(ioc), ssl_ctx_(ssl_ctx), resolve_results_(resolve_results),
      callback_(cb), deadline_timer_(ioc), stream_(ioc, ssl_ctx_), req_(req) {}

void HttpsClientSession::on_connect() {
    LOG(trace) << "on connect";
    stream_.async_handshake(ssl::stream_base::client,
                            std::bind(&HttpsClientSession::on_handshake,
                                      shared_from_this(),
                                      std::placeholders::_1));
}

void HttpsClientSession::on_handshake(boost::system::error_code ec) {
    if (ec) {
        LOG(error) << "handshake failed:" << ec.message();
        LOG(error) << stream_.lowest_layer().remote_endpoint().address() << ":"
                   << stream_.lowest_layer().remote_endpoint().port();
        return;
    }

    http::async_write(stream_, *req_,
                      std::bind(&HttpsClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpsClientSession::on_write(error_code ec, size_t bytes_transferred) {

    LOG(trace) << "on write";
    if (ec) {
        LOG(error) << "Error on write, ec: " << ec.value()
                   << ". Message: " << ec.message();
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    LOG(trace) << "Successfully transferred " << bytes_transferred << " bytes";

    // Receive the HTTP response
    http::async_read(stream_, buffer_, res_,
                     std::bind(&HttpsClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

void HttpsClientSession::on_read(error_code ec, size_t bytes_transferred) {

    LOG(trace) << "Successfully received " << bytes_transferred << " bytes";

    std::shared_ptr<std::string> body = nullptr;

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {
            body = std::make_shared<std::string>(res_.body());
            trigger_callback(SNodeError::NO_ERROR, std::move(body));
        }

    } else {

        /// Do we need to handle `operation aborted` separately here (due to
        /// deadline timer)?
        LOG(error) << "Error on read: " << ec.value()
                   << ". Message: " << ec.message();
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
    }

    // Gracefully close the socket
    do_close();

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        LOG(error) << "ec: " << ec.value() << ". Message: " << ec.message();
        return;
    }

    // If we get here then the connection is closed gracefully
}

void HttpsClientSession::start() {
    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (!SSL_set_tlsext_host_name(stream_.native_handle(), "service node")) {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                    boost::asio::error::get_ssl_category()};
        LOG(error) << ec.message();
        return;
    }
    boost::asio::async_connect(
        stream_.next_layer(), resolve_results_,
        [this, self = shared_from_this()](boost::system::error_code ec,
                                          const tcp::endpoint& endpoint) {
            /// TODO: I think I should just call again if ec ==
            /// EINTR
            if (ec) {
                LOG(error) << boost::format("Could not connect to %1%, "
                                            "message: %2% (%3%)") %
                                  endpoint % ec.message() % ec.value();
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
                    LOG(error) << boost::format("Error(%1%): %2%\n") %
                                      ec.value() % ec.message();
                }
            } else {
                LOG(error) << "client socket timed out";
                self->do_close();
            }
        });
}

void HttpsClientSession::trigger_callback(SNodeError error,
                                          std::shared_ptr<std::string>&& body) {
    ioc_.post(std::bind(callback_, sn_response_t{error, body}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

void HttpsClientSession::do_close() {
    // Gracefully close the stream
    stream_.async_shutdown(std::bind(&HttpsClientSession::on_shutdown,
                                     shared_from_this(),
                                     std::placeholders::_1));
}

void HttpsClientSession::on_shutdown(boost::system::error_code ec) {
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    }
    if (ec) {
        LOG(error) << "could not shutdown stream gracefully: " << ec.message();
    }

    // If we get here then the connection is closed gracefully
}

/// We execute callback (if haven't already) here to make sure it is called
HttpsClientSession::~HttpsClientSession() {

    if (!used_callback_) {
        // If we destroy the session before posting the callback,
        // it must be due to some error
        ioc_.post(std::bind(callback_,
                            sn_response_t{SNodeError::ERROR_OTHER, nullptr}));
    }
}
} // namespace loki
