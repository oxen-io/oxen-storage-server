#pragma once

#include "utils.h"
#include "mqbase.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/snode/service_node.h>

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

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
    QUIC(snode::ServiceNode& snode,
         rpc::RequestHandler& rh,
         rpc::RateLimiter& rl,
         std::span<const Address> bind,
         const crypto::ed25519_seckey& sk);

    void startup_endpoint();

    void notify(std::vector<connection_id>&, std::string_view notification) override;

    void reachability_test(std::shared_ptr<snode::sn_test> test) override;

    quic::Loop loop{};

  private:
    std::shared_ptr<quic::TLSCreds> tls_creds;
    std::vector<std::shared_ptr<quic::Endpoint>> endpoints;
    quic::Endpoint* reach_ep = nullptr;

    rpc::RequestHandler& request_handler;

    std::shared_ptr<quic::Endpoint> create_endpoint();

    void handle_request(quic::message msg, size_t ep_idx);

    void handle_onion_request(quic::message msg);

    void handle_monitor_message(quic::message msg, size_t ep_idx);

    void handle_ping(quic::message msg);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace oxenss::server
