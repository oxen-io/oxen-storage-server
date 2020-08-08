#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace lokimq {
class LokiMQ;
struct Allow;
class Message;
} // namespace lokimq

using lokimq::LokiMQ;

namespace loki {

struct lokid_key_pair_t;
class ServiceNode;
class RequestHandler;

class LokimqServer {

    std::unique_ptr<LokiMQ> lokimq_;

    // Has information about current SNs
    ServiceNode* service_node_;

    RequestHandler* request_handler_;

    // Get nodes' address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(lokimq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(lokimq::Message& message);

    void handle_onion_request(lokimq::Message& message);

    uint16_t port_ = 0;

  public:
    LokimqServer(uint16_t port);
    ~LokimqServer();

    // Initialize lokimq
    void init(ServiceNode* sn, RequestHandler* rh,
              const lokid_key_pair_t& keypair);

    uint16_t port() { return port_; }

    /// True if LokiMQ instance has been set
    explicit operator bool() const { return (bool) lokimq_; }
    /// Dereferencing via * or -> accesses the contained LokiMQ instance.
    LokiMQ& operator*() const { return *lokimq_; }
    LokiMQ* operator->() const { return lokimq_.get(); }
};

} // namespace loki
