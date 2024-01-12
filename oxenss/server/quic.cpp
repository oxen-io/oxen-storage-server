#include "quic.h"
#include "oxenss/rpc/rate_limiter.h"

#include <oxenss/rpc/request_handler.h>

namespace oxenss::server {

static auto logcat = log::Cat("ssquic");

QUIC::QUIC(
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        const Address& bind,
        const crypto::ed25519_seckey& sk) :
        local{bind},
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_seckey(sk.str())},
        ep{network->endpoint(
                local,
                [this](oxen::quic::connection_interface& ci, uint64_t ec) {
                    on_conn_closed(ci, ec);
                })},
        request_handler{rh},
        command_handler{[this](quic::message m) { handle_request(std::move(m)); }} {
    request_handler_ = &rh;
    rate_limiter_ = &rl;
}

void QUIC::startup_endpoint() {
    ep->listen(tls_creds, [&](oxen::quic::connection_interface& c) {
        c.queue_incoming_stream<oxen::quic::BTRequestStream>(command_handler);
    });
}

void QUIC::on_conn_closed(oxen::quic::connection_interface& conn_interface, uint64_t ec) {
    const auto& remote = conn_interface.local();
    const auto& scid = conn_interface.scid();

    log::debug(logcat, "Purging quic connection to remote address:{} (ec: {})", remote, ec);

    if (const auto& itr = conns.find(scid); itr != conns.end()) {
        conns.erase(itr);
        log::trace(logcat, "Purged connection object (CID:{})", scid);
    }

    log::debug(
            logcat,
            "Quic connection (CID:{}) to remote address:{} purged successfully",
            scid,
            remote);
}

void QUIC::handle_monitor_message(oxen::quic::message m) {
    handle_monitor(
            m.body(),
            [&m](std::string response) { m.respond(std::move(response)); },
            m.stream()->conn_id());
}

void QUIC::handle_request(oxen::quic::message m) {
    auto name = m.endpoint();

    if (handle_client_rpc(
                name,
                m.body(),
                m.stream()->remote().host(),
                [m = std::move(m)](http::response_code status, std::string_view body) {
                    m.respond(body);
                }))
        return;

    if (name == "monitor")
        return handle_monitor_message(std::move(m));

    throw quic::no_such_endpoint{};
}

nlohmann::json QUIC::wrap_response(
        [[maybe_unused]] const http::response_code& status, nlohmann::json body) const {
    // For QUIC requests we always wrap the result into a [CODE, BODY] list (even for successes).
    // This is different from the OMQ because, in OMQ, messages are multi-part and so we can
    // disambiguate success-with-body from failure-with-body by looking at the number of parts; here
    // we can't, so we always make responses a 2-element list.
    auto res = nlohmann::json::array();
    res.push_back(status.first);
    res.push_back(std::move(body));
    return res;
}

void QUIC::notify(std::vector<connection_id>& conns, std::string_view notification) {
    for (const auto& c : conns)
        if (auto* cid = std::get_if<oxen::quic::ConnectionID>(&c))  // FIXME: ConnRef or whatever
            if (auto conn = ep->get_conn(*cid))
                if (auto str = conn->get_stream<oxen::quic::BTRequestStream>(0))
                    str->command("notify", notification);
}

}  // namespace oxenss::server
