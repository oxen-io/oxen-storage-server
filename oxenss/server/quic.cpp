#include "quic.h"

#include <oxenss/rpc/request_handler.h>

namespace oxenss::quic {

Connection::Connection(
        std::shared_ptr<oxen::quic::connection_interface>& c,
        std::shared_ptr<oxen::quic::BTRequestStream>& s) :
        conn{c}, control_stream{s} {}

Quic::Quic(
        rpc::RequestHandler& rh,
        const oxen::quic::Address& bind,
        const crypto::ed25519_seckey& sk) :
        local{bind},
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_seckey(sk.str())},
        ep{startup_endpoint()},
        request_handler{rh} {}

std::shared_ptr<oxen::quic::Endpoint> Quic::startup_endpoint() {
    auto ep = network->endpoint(
            local,
            [this](oxen::quic::connection_interface& ci) { return on_conn_open(ci); },
            [this](oxen::quic::connection_interface& ci, uint64_t ec) {
                return on_conn_closed(ci, ec);
            },
            [this](oxen::quic::dgram_interface& di, bstring dgram) {
                recv_data_message(di, dgram);
            });
    ep->listen(
            tls_creds,
            [&](oxen::quic::Connection& c,
                oxen::quic::Endpoint& e,
                std::optional<int64_t> id) -> std::shared_ptr<oxen::quic::Stream> {
                if (id && id == 0) {
                    auto s = std::make_shared<oxen::quic::BTRequestStream>(c, e);
                    register_commands(s);
                    return s;
                }
                return std::make_shared<oxen::quic::Stream>(c, e);
            });
    return ep;
}

void Quic::register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s) {
    for (const auto& [n, cb] : rpc::RequestHandler::client_rpc_endpoints) {
        std::string name{n};

        s->register_command(name, [this, name, func = cb](oxen::quic::message m) {
            std::invoke(&Quic::handle_request, this, name, std::move(m));
        });
    }
}

void Quic::handle_request(std::string name, oxen::quic::message m) {
    if (m.timed_out) {
        //
    }

    if (auto itr = rpc::RequestHandler::client_rpc_endpoints.find(name);
        itr != rpc::RequestHandler::client_rpc_endpoints.end()) {
        //
    }

    try {
        //
    } catch (...) {
        log::warning(logcat, "Shit man");
        m.respond(serialize_response({{"STATUS", error::EXCEPTION}}));
        throw;
    }
}

}  // namespace oxenss::quic
