#include "quic.h"
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "../snode/service_node.h"

namespace oxenss::server {

static auto logcat = log::Cat("ssquic");

QUIC::QUIC(
        snode::ServiceNode& snode,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        const Address& bind,
        const crypto::ed25519_seckey& sk) :
        local{bind},
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_seckey(sk.str())},
        ep{network->endpoint(local)},
        request_handler{rh},
        command_handler{[this](quic::message m) { handle_request(std::move(m)); }} {
    service_node_ = &snode;
    request_handler_ = &rh;
    rate_limiter_ = &rl;
}

void QUIC::startup_endpoint() {
    ep->listen(tls_creds, [&](oxen::quic::connection_interface& c) {
        c.queue_incoming_stream<oxen::quic::BTRequestStream>(command_handler);
    });
}

void QUIC::handle_monitor_message(oxen::quic::message m) {
    handle_monitor(
            m.body(),
            [&m](std::string response) { m.respond(std::move(response)); },
            m.stream()->reference_id);
}

void QUIC::handle_ping(oxen::quic::message m) {
    log::debug(logcat, "Remote pinged me");
    service_node_->update_last_ping(snode::ReachType::QUIC);
    m.respond("pong");
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

    if (name == "snode_ping")
        return handle_ping(std::move(m));

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
        if (auto* cid = std::get_if<oxen::quic::ConnectionID>(&c))
            if (auto conn = ep->get_conn(*cid))
                if (auto str = conn->get_stream<oxen::quic::BTRequestStream>(0))
                    str->command("notify", notification);
}

void QUIC::reachability_test(std::shared_ptr<snode::sn_test> test) {
    if (!service_node_->hf_at_least(snode::QUIC_REACHABILITY_TESTING))
        return test->add_result(true);

    auto& sn = test->sn;
    auto conn = ep->connect(
            {sn.pubkey_ed25519.view(), sn.ip, sn.omq_quic_port},
            tls_creds,
            oxen::quic::opt::handshake_timeout{5s});
    auto s = conn->open_stream<oxen::quic::BTRequestStream>();
    s->command("snode_ping", ""s, [test = std::move(test)](const oxen::quic::message& m) {
        if (m.timed_out || m.body() != "pong"sv) {
            log::debug(
                    logcat,
                    "QUIC reachability test failed for {}: {}",
                    test->sn.pubkey_legacy,
                    m.timed_out ? "timeout" : "unexpected response");
            test->add_result(false);
        } else {
            test->add_result(true);
        }
        if (auto conn = m.stream()->endpoint.get_conn(m.conn_rid()))
            conn->close_connection();
    });
}

}  // namespace oxenss::server
