#include "quic.h"

namespace oxenss::quic {

Connection::Connection(
        std::shared_ptr<oxen::quic::connection_interface>& c,
        std::shared_ptr<oxen::quic::BTRequestStream>& s) :
        conn{c}, control_stream{s} {}

Quic::Quic(const oxen::quic::Address& bind, const crypto::ed25519_seckey& sk) : 
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_keys()}
{}

}  // namespace oxenss::quic