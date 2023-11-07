#pragma once

#include "utils.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>

#include <quic.hpp>

namespace oxenss::rpc {
class RequestHandler;
}  // namespace oxenss::rpc

namespace oxenss::quic {

static auto logcat = log::Cat("quic");

struct Connection {

    Connection(
            std::shared_ptr<oxen::quic::connection_interface>& c,
            std::shared_ptr<oxen::quic::BTRequestStream>& s);

  private:
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> control_stream;

  public:
    //
};

struct Quic {

    Quic(rpc::RequestHandler& rh,
         const oxen::quic::Address& bind,
         const crypto::ed25519_seckey& sk);

  private:
    const oxen::quic::Address local;
    std::unique_ptr<oxen::quic::Network> network;
    std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<oxen::quic::Endpoint> ep;

    const rpc::RequestHandler& request_handler;

    std::unordered_map<oxen::quic::ConnectionID, std::shared_ptr<quic::Connection>> conns;

    std::shared_ptr<oxen::quic::Endpoint> startup_endpoint();

    void on_conn_open(oxen::quic::connection_interface& ci);
    void on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec);

    void recv_data_message(oxen::quic::dgram_interface&, bstring);

    void register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s);

    void handle_request(std::string name, oxen::quic::message m);

  public:
    template <typename... Opt>
    bool establish_connection(const oxen::quic::Address& addr, Opt&&... opts) {
        try {
            auto conn_interface = ep->connect(addr, tls_creds, std::forward<Opt>(opts)...);

            // emplace immediately for connection open callback to find scid
            auto [itr, b] = conns.emplace(conn_interface->scid(), nullptr);

            auto control_stream =
                    conn_interface->template get_new_stream<oxen::quic::BTRequestStream>();
            itr->second = std::make_shared<quic::Connection>(conn_interface, control_stream);

            return true;
        } catch (...) {
            log::error(logcat, "Error: failed to establish connection to {}", addr);
            return false;
        }
    }
};

}  // namespace oxenss::quic
