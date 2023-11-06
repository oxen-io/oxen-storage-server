#pragma once

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>

#include <quic.hpp>

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

    Quic(const oxen::quic::Address& bind, const crypto::ed25519_seckey& sk);

  private:
    std::unique_ptr<oxen::quic::Network> network;
    std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<oxen::quic::Endpoint> ep;

  public:
    
    template<typename... Opt>
    bool establish_connection(const oxen::quic::Address& addr, Opt&&... opts)
    {
        try
        {
            auto conn_interface =
                ep->connect(addr, link_manager.tls_creds, std::forward<Opt>(opts)...);

            // emplace immediately for connection open callback to find scid
            connid_map.emplace(conn_interface->scid(), rc.router_id());
            auto [itr, b] = conns.emplace(rc.router_id(), nullptr);

            auto control_stream =
                conn_interface->template get_new_stream<oxen::quic::BTRequestStream>();
            itr->second = std::make_shared<quic::Connection>(conn_interface, control_stream, rc);

            return true;
        }
        catch (...)
        {
            log::error(logcat, "Error: failed to establish connection to {}", remote);
            return false;
        }
    }
};



}  // namespace oxenss::quic