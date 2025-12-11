#include "quic.h"
#include <sodium/crypto_generichash_blake2b.h>
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "../snode/service_node.h"
#include "../snode/sn_test.h"
#include "omq.h"
#include "utils.h"

#include <oxen/quic/gnutls_crypto.hpp>

namespace oxenss::server {

static auto logcat = log::Cat("ssquic");

static constexpr std::string_view static_secret_key = "Storage Server QUIC shared secret hash key";
static quic::opt::static_secret make_endpoint_static_secret(const crypto::ed25519_seckey& sk) {
    std::vector<unsigned char> secret;
    secret.resize(32);

    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st,
            reinterpret_cast<const unsigned char*>(static_secret_key.data()),
            static_secret_key.size(),
            secret.size());
    crypto_generichash_blake2b_update(&st, sk.data(), sk.size());
    crypto_generichash_blake2b_final(
            &st, reinterpret_cast<unsigned char*>(secret.data()), secret.size());

    return quic::opt::static_secret{std::move(secret)};
}

static constexpr auto ALPN = "oxenstorage";

QUIC::QUIC(
        snode::ServiceNode& snode,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::span<const Address> bind,
        const crypto::ed25519_seckey& sk) :
        tls_creds{quic::GNUTLSCreds::make_from_ed_seckey(sk.str())}, request_handler{rh} {
    service_node_ = &snode;
    request_handler_ = &rh;
    rate_limiter_ = &rl;

    static_cast<quic::GNUTLSCreds*>(tls_creds.get())->enable_inbound_0rtt();

    if (bind.empty())
        throw std::invalid_argument{"No bind addresses given to QUIC listener!"};

    endpoints.reserve(bind.size());
    for (auto& a : bind) {
        endpoints.push_back(quic::Endpoint::endpoint(
                loop, a, make_endpoint_static_secret(sk), quic::opt::alpns{ALPN}));
        if (!reach_ep && (a.is_ipv4() || (a.is_any_addr() && a.dual_stack)))
            reach_ep = endpoints.back().get();
    }

    if (!reach_ep)
        throw std::invalid_argument{"No IPv4 bind address given to QUIC listener!"};

    // Add a category to OMQ for handling incoming quic request jobs
    service_node_->omq_server()->add_category(
            "quic",
            oxenmq::AuthLevel::basic,
            2,    // minimum # of threads reserved threads for this category
            1000  // max queued requests
    );
}

void QUIC::startup_endpoint() {
    size_t ep_idx = 0;
    for (auto& ep : endpoints) {
        auto handler = [this, ep_idx](quic::message m) { handle_request(std::move(m), ep_idx); };
        ep->listen(
                tls_creds,
                // Stream constructor: all incoming streams become BTRequestStreams, allowing
                // clients to use multiple streams to send higher/lower priority data in parallel by
                // juggling streams.
                [handler = std::move(handler)](
                        quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                    return e.loop.make_shared<quic::BTRequestStream>(c, e, handler);
                });
        ep_idx++;
    }
}

void QUIC::handle_monitor_message(quic::message msg, size_t ep_idx) {

    auto body = msg.body();
    auto refid = msg.stream()->reference_id;
    handle_monitor(
            body,
            [msg = std::move(msg)](std::string response) { msg.respond(std::move(response)); },
            std::pair{ep_idx, refid});
}

void QUIC::handle_ping(quic::message msg) {
    log::debug(logcat, "Remote pinged me");
    service_node_->update_last_ping(snode::ReachType::QUIC);
    msg.respond("pong");
}

void QUIC::handle_request(quic::message msg, size_t ep_idx) {
    auto& omq = *service_node_->omq_server();
    auto remote_host = msg.stream()->get_conn()->remote();
    auto remote_ip =
            (remote_host.is_ipv4() ? remote_host.mapped_ipv4_as_ipv6() : remote_host).to_ipv6();

    auto name = msg.endpoint();
    if (!(name == "snode_ping" || name == "monitor" || name == "onion_req" ||
          rpc::RequestHandler::client_rpc_endpoints.count(name)))
        throw quic::no_such_endpoint{};

    // We handle everything inside an inject task because if we do *anything* that requires
    // `sn_mutex_` we could deadlock (because the `open_stream` we do in reachability testing is
    // synchronous, but is also called with the `sn_mutex_` held).
    omq.inject_task(
            "quic",
            "quic:{}"_format(msg.endpoint()),
            remote_host.host(),
            [this, msg, remote_ip, ep_idx] {
                auto name = msg.endpoint();

                if (name == "snode_ping")
                    handle_ping(std::move(msg));

                if (name == "monitor")
                    handle_monitor_message(std::move(msg), ep_idx);

                if (name == "onion_req")
                    handle_onion_request(std::move(msg));

                handle_client_rpc(
                        name,
                        msg.body(),
                        remote_ip,
                        [msg](http::response_code code, std::string_view res_body) {
                            if (code.first == http::OK.first)
                                msg.respond(res_body);
                            else
                                msg.respond(
                                        "{} {}\n\n{}"_format(code.first, code.second, res_body),
                                        true);
                        });
            });
}

void QUIC::handle_onion_request(quic::message msg) {

    auto started = std::chrono::steady_clock::now();
    try {
        rpc::OnionRequestMetadata onion{
                crypto::x25519_pubkey{},
                [msg, started](rpc::Response res) {
                    log::debug(
                            logcat,
                            "Got an onion response ({} {}) as edge node (after {})",
                            res.status.first,
                            res.status.second,
                            util::friendly_duration(std::chrono::steady_clock::now() - started));

                    std::string json_body;
                    std::string_view body;
                    if (auto json = std::get_if<nlohmann::json>(&res.body)) {
                        json_body = json->dump();
                        body = json_body;
                    } else if (auto* binary = std::get_if<std::span<const std::byte>>(&res.body)) {
                        body = {reinterpret_cast<const char*>(binary->data()), binary->size()};
                    } else {
                        body = rpc::view_body(res);
                    }

                    if (res.status.first != http::OK.first)
                        msg.respond(
                                "{} {}\n\n{}"_format(res.status.first, res.status.second, body),
                                true);
                    else
                        msg.respond(body);
                },
                0,  // hopno
                crypto::EncryptType::aes_gcm,
        };

        auto [ciphertext, json_req] = rpc::parse_combined_payload(msg.body());

        onion.ephem_key = rpc::extract_x25519_from_hex(
                json_req.at("ephemeral_key").get_ref<const std::string&>());

        if (auto it = json_req.find("enc_type"); it != json_req.end())
            onion.enc_type = crypto::parse_enc_type(it->get_ref<const std::string&>());
        // Otherwise stay at default aes-gcm

        // Allows a fake starting hop number (to make it harder for
        // intermediate hops to know where they are).  If omitted, defaults
        // to 0.
        if (auto it = json_req.find("hop_no"); it != json_req.end())
            onion.hop_no = std::max(0, it->get<int>());

        request_handler_->process_onion_req(ciphertext, std::move(onion));

    } catch (const std::exception& e) {
        auto err = fmt::format("Error parsing onion request: {}", e.what());
        log::error(logcat, "{}", err);
        msg.respond(
                "{} {}\n\n{}"_format(http::BAD_REQUEST.first, http::BAD_REQUEST.second, err), true);
    }
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
    for (const auto& c : conns) {
        if (auto* quic_id = std::get_if<std::pair<size_t, quic::ConnectionID>>(&c)) {
            auto& [ep_idx, cid] = *quic_id;
            assert(ep_idx < endpoints.size());
            if (auto conn = endpoints[ep_idx]->get_conn(cid))
                if (auto str = conn->get_stream<quic::BTRequestStream>(0))
                    str->command("notify", notification);
        }
    }
}

void QUIC::reachability_test(std::shared_ptr<snode::sn_test> test) {
    auto maybe_ct = service_node_->contacts().find(test->pubkey);
    if (!maybe_ct || !*maybe_ct)
        // If we don't have any usable contact info then don't do anything: oxend will already fail
        // a node that hasn't broadcast usable contact info, so we don't need to worry about testing
        // it here.
        return;
    const auto& ct = *maybe_ct;

    auto conn = reach_ep->connect(
            {ct.pubkey_ed25519.view(), ct.ip, ct.omq_quic_port},
            tls_creds,
            quic::opt::handshake_timeout{5s});
    auto s = conn->open_stream<quic::BTRequestStream>();
    s->command("snode_ping", ""s, [test = std::move(test), this](const quic::message& m) mutable {
        bool passed;
        if (m.timed_out || m.body() != "pong"sv) {
            log::debug(
                    logcat,
                    "QUIC reachability test failed for {}: {}",
                    test->pubkey,
                    m.timed_out ? "timeout" : "unexpected response");
            passed = false;
        } else {
            log::debug(
                    logcat,
                    "Successful response to QUIC reachability ping test of {}",
                    test->pubkey);
            passed = true;
        }
        if (auto conn = m.stream()->endpoint.get_conn(m.conn_rid()))
            conn->close_connection();

        // Defer this to an omq task; the same deadlock-avoidance logic described in
        // handle_request applies here.
        service_node_->omq_server()->inject_task(
                "quic", "quic:(reach_report)", "", [test = std::move(test), passed]() {
                    test->add_result(passed);
                });
    });
}

}  // namespace oxenss::server
