#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace oxenmq {
class OxenMQ;
struct Allow;
class Message;
} // namespace oxenmq

using oxenmq::OxenMQ;

namespace oxen {

struct oxend_key_pair_t;
class ServiceNode;
class RequestHandler;

class OxenmqServer {

    std::unique_ptr<OxenMQ> oxenmq_;

    // Has information about current SNs
    ServiceNode* service_node_;

    RequestHandler* request_handler_;

    // Get nodes' address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(oxenmq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(oxenmq::Message& message);

    // v2 indicates whether to use the new (v2) protocol
    void handle_onion_request(oxenmq::Message& message, bool v2);

    void handle_get_logs(oxenmq::Message& message);

    void handle_get_stats(oxenmq::Message& message);

    uint16_t port_ = 0;

    // Access keys for the 'service' category as binary
    std::vector<std::string> stats_access_keys;

  public:
    OxenmqServer(uint16_t port);
    ~OxenmqServer();

    // Initialize oxenmq
    void init(ServiceNode* sn, RequestHandler* rh,
              const oxend_key_pair_t& keypair,
              const std::vector<std::string>& stats_access_key);

    uint16_t port() { return port_; }

    /// True if OxenMQ instance has been set
    explicit operator bool() const { return (bool)oxenmq_; }
    /// Dereferencing via * or -> accesses the contained OxenMQ instance.
    OxenMQ& operator*() const { return *oxenmq_; }
    OxenMQ* operator->() const { return oxenmq_.get(); }
};

} // namespace oxen
