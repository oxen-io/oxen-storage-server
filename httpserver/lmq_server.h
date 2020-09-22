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

    // v2 indicates whether to use the new (v2) protocol
    void handle_onion_request(lokimq::Message& message, bool v2);

    void handle_notify_add_pubkey(lokimq::Message& message);

    void handle_notify_get_subscriber_count(lokimq::Message& message);

    bool check_pn_server_pubkey(const std::string& pk) const;

    uint16_t port_ = 0;

    // binary stored in a string
    std::string pn_server_key_;

  public:
    LokimqServer(uint16_t port);
    ~LokimqServer();

    // Initialize lokimq
    void init(ServiceNode* sn, RequestHandler* rh,
              const lokid_key_pair_t& keypair);

    uint16_t port() { return port_; }

    /// True if LokiMQ instance has been set
    explicit operator bool() const { return (bool)lokimq_; }
    /// Dereferencing via * or -> accesses the contained LokiMQ instance.
    LokiMQ& operator*() const { return *lokimq_; }
    LokiMQ* operator->() const { return lokimq_.get(); }
};

} // namespace loki
