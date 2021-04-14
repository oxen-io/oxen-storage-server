#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <oxenmq/oxenmq.h>

#include "sn_record.h"

namespace oxen {

struct oxend_key_pair_t;
class ServiceNode;
class RequestHandler;

void omq_logger(oxenmq::LogLevel level, const char* file, int line,
        std::string message);

class OxenmqServer {

    oxenmq::OxenMQ omq_;
    oxenmq::ConnectionID oxend_conn_;

    // Has information about current SNs
    ServiceNode* service_node_ = nullptr;

    RequestHandler* request_handler_ = nullptr;

    // Get node's address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(oxenmq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(oxenmq::Message& message);

    // v2 indicates whether to use the new (v2) protocol
    void handle_onion_request(oxenmq::Message& message, bool v2);

    void handle_get_logs(oxenmq::Message& message);

    void handle_get_stats(oxenmq::Message& message);

    // Access keys for the 'service' category as binary
    std::unordered_set<std::string> stats_access_keys_;

    void connect_oxend(const oxenmq::address& oxend_rpc);

  public:
    OxenmqServer(
            const sn_record_t& me,
            const x25519_seckey& privkey,
            const std::vector<x25519_pubkey>& stats_access_keys_hex);

    // Initialize oxenmq
    void init(ServiceNode* sn, RequestHandler* rh, oxenmq::address oxend_rpc);

    /// Dereferencing via * or -> accesses the contained OxenMQ instance.
    oxenmq::OxenMQ& operator*() { return omq_; }
    oxenmq::OxenMQ* operator->() { return &omq_; }

    // Returns the OMQ ConnectionID for the connection to oxend.
    const oxenmq::ConnectionID& oxend_conn() const { return oxend_conn_; }

    // Invokes a request to the local oxend; given arguments (which must contain at least the
    // request name and a callback) are forwarded as `omq.request(connid, ...)`.
    template <typename... Args>
    void oxend_request(Args&&... args) {
        assert(oxend_conn_);
        omq_.request(oxend_conn(), std::forward<Args>(args)...);
    }

    // Sends a one-way message to the local oxend; arguments are forwarded as `omq.send(connid,
    // ...)` (and must contain at least a command name).
    template <typename... Args>
    void oxend_send(Args&&... args) {
        assert(oxend_conn_);
        omq_.send(oxend_conn(), std::forward<Args>(args)...);
    }
};

} // namespace oxen
