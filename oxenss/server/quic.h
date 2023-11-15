#pragma once

#include "utils.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>

#include <quic.hpp>

namespace oxenss::rpc {
class RequestHandler;
struct Response;
}  // namespace oxenss::rpc

namespace oxenss::server {
class OMQ;
}

namespace oxenss::quic {

static auto logcat = log::Cat("quic");

struct Endpoint;

using quic_callback = std::function<void(oxen::quic::message)>;
using Address = oxen::quic::Address;
using RemoteAddress = oxen::quic::RemoteAddress;
using connection_established_callback = oxen::quic::connection_established_callback;
using connection_closed_callback = oxen::quic::connection_closed_callback;
using quic_interface = oxen::quic::connection_interface;

inline constexpr uint64_t PING_OK{0};

/// This object wraps callbacks to execute logic at connection open, after which the
/// connection is immediately closed. This is useful in reachability testing, as we
/// want to connect, check if the pubkey was validated during the handshake, and close
/// after reporting the results.
struct connection_killer {
    connection_established_callback cb;

    explicit connection_killer(connection_established_callback f) : cb{std::move(f)} {}

    void operator()(quic_interface& qi) {
        cb(qi);
        qi.close_connection(PING_OK);
    }
};

enum class message_type { REQUEST = 0, DATAGRAM = 1 };

struct Connection {
    friend struct Endpoint;

    Connection(
            std::shared_ptr<oxen::quic::connection_interface>& c,
            std::shared_ptr<oxen::quic::BTRequestStream>& s);

    void send(std::string method, std::string body, quic_callback f = nullptr);

  private:
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> control_stream;
};

struct Endpoint {
    static std::shared_ptr<Endpoint> make(
            rpc::RequestHandler& rh,
            server::OMQ& q,
            const Address& bind,
            const crypto::ed25519_seckey& sk);

    void ping(
            const RemoteAddress&,
            connection_established_callback = nullptr,
            connection_closed_callback = nullptr);

    std::shared_ptr<quic::Connection> get_conn(const oxen::quic::ConnectionID& cid) {
        if (auto itr = conns.find(cid); itr != conns.end())
            return itr->second;

        return nullptr;
    }

    void startup_endpoint();

  private:
    Endpoint(
            rpc::RequestHandler& rh,
            server::OMQ& q,
            const Address& bind,
            const crypto::ed25519_seckey& sk);

    const Address local;
    std::unique_ptr<oxen::quic::Network> network;
    std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<oxen::quic::Endpoint> ep;

    rpc::RequestHandler& request_handler;
    server::OMQ& omq;

    // Holds all connections currently being managed by the quic endpoint
    std::unordered_map<oxen::quic::ConnectionID, std::shared_ptr<quic::Connection>> conns;

    std::shared_ptr<oxen::quic::Endpoint> create_endpoint();

    void on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec);

    void register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s);

    void process_rpc(rpc::Response resp, oxen::quic::message m, bool bt_encoded);

    void handle_storage_request(std::string name, oxen::quic::message m, bool forwarded = false);

    void handle_onion_request(oxen::quic::message m);

    void handle_monitor_message(oxen::quic::message m);

  public:
    template <typename... Opt>
    void establish_connection(const RemoteAddress& addr, Opt&&... opts) {
        try {
            auto conn_interface = ep->connect(addr, tls_creds, std::forward<Opt>(opts)...);

            // emplace immediately for connection open callback to find scid
            auto [itr, b] = conns.emplace(conn_interface->scid(), nullptr);

            auto control_stream =
                    conn_interface->template get_new_stream<oxen::quic::BTRequestStream>();
            itr->second = std::make_shared<quic::Connection>(conn_interface, control_stream);
        } catch (...) {
            log::error(logcat, "Error: failed to establish connection to {}", addr);
            throw;
        }
    }
};

}  // namespace oxenss::quic
