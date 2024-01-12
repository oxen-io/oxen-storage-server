#pragma once

#include "oxenss/rpc/rate_limiter.h"
#include "utils.h"
#include "mqbase.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>

#include <quic.hpp>

namespace oxenss::rpc {
class RequestHandler;
}  // namespace oxenss::rpc

namespace oxenss::server {

namespace quic = oxen::quic;

using quic_callback = std::function<void(quic::message)>;
using Address = quic::Address;

struct PendingRequest {
    std::optional<std::string> name = std::nullopt;
    std::string body;
    quic_callback func = nullptr;

    // Constructor
    PendingRequest(std::string name, std::string body, quic_callback func) :
            name{std::move(name)}, body{std::move(body)}, func{std::move(func)} {}
    PendingRequest(std::string_view name, std::string_view body, quic_callback func) :
            name{name}, body{body}, func{std::move(func)} {}
};

using RequestQueue = std::deque<PendingRequest>;

class QUIC : public MQBase {
  public:
    QUIC(rpc::RequestHandler& rh,
         rpc::RateLimiter& rl,
         const Address& bind,
         const crypto::ed25519_seckey& sk);

    void startup_endpoint();

    void notify(std::vector<connection_id>&, std::string_view notification) override;

  private:

    const Address local;
    std::unique_ptr<quic::Network> network;
    std::shared_ptr<quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<quic::Endpoint> ep;

    rpc::RequestHandler& request_handler;
    std::function<void(quic::message m)> command_handler;

    // Holds all connections currently being managed by the quic endpoint
    std::unordered_map<quic::ConnectionID, std::shared_ptr<quic::Connection>> conns;

    std::shared_ptr<quic::Endpoint> create_endpoint();

    void on_conn_closed(quic::connection_interface& ci, uint64_t ec);

    void handle_request(quic::message m);

    void handle_monitor_message(quic::message m);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace oxenss::server
