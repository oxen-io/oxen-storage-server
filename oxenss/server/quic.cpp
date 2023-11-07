#include "quic.h"
#include "omq.h"

#include <oxenss/rpc/request_handler.h>

namespace oxenss::quic {

Connection::Connection(
        std::shared_ptr<oxen::quic::connection_interface>& c,
        std::shared_ptr<oxen::quic::BTRequestStream>& s) :
        conn{c}, control_stream{s} {}

std::shared_ptr<Endpoint> Endpoint::make(
        rpc::RequestHandler& rh,
        server::OMQ& q,
        const Address& bind,
        const crypto::ed25519_seckey& sk) {
    std::shared_ptr<Endpoint> ep{new Endpoint{rh, q, bind, sk}};
    return ep;
}

Endpoint::Endpoint(
        rpc::RequestHandler& rh,
        server::OMQ& q,
        const Address& bind,
        const crypto::ed25519_seckey& sk) :
        local{bind},
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_seckey(sk.str())},
        ep{create_endpoint()},
        request_handler{rh},
        omq{q} {}

std::shared_ptr<oxen::quic::Endpoint> Endpoint::create_endpoint() {
    auto ep = network->endpoint(local, [this](oxen::quic::connection_interface& ci, uint64_t ec) {
        on_conn_closed(ci, ec);
    });
    return ep;
}

void Endpoint::startup_endpoint() {
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
}

void Connection::send(std::string method, std::string body, quic_callback f) {
    control_stream->command(std::move(method), std::move(body), std::move(f));
}

bool Endpoint::send(
        oxen::quic::ConnectionID cid, std::string method, std::string body, quic_callback func) {

    if (auto conn = get_conn(cid)) {
        conn->control_stream->command(std::move(method), std::move(body), std::move(func));
        return true;
    }

    return false;
}

void Endpoint::on_conn_closed(oxen::quic::connection_interface& conn_interface, uint64_t ec) {
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

void Endpoint::register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s) {
    // register storage.{endpoint} commands
    for (const auto& [n, cb] : rpc::RequestHandler::client_rpc_endpoints) {
        std::string name{n};

        s->register_command(name, [this, name](oxen::quic::message m) {
            std::invoke(&Endpoint::handle_request, this, name, std::move(m), false);
        });
    }

    s->register_command("monitor", [this](oxen::quic::message m) {
        std::invoke(&Endpoint::handle_monitor_message, this, std::move(m));
    });
}

void Endpoint::handle_monitor_message(oxen::quic::message m) {
    if (m.timed_out) {
        log::info(logcat, "Request (method:{}) timed out!");
        return;
    }

    std::string body{m.body()};
    const auto& front = body.front();
    std::string result;
    std::vector<sub_info> subs;

    try {
        if (front == 'd') {
            oxenc::bt_dict_producer out;
            handle_monitor_message_single(oxenc::bt_dict_consumer{body}, out, subs);
            result = std::move(out).str();
        } else {
            oxenc::bt_list_producer out;
            oxenc::bt_list_consumer l{body};
            while (!l.is_finished())
                handle_monitor_message_single(l.consume_dict_consumer(), out.append_dict(), subs);
            result = std::move(out).str();
        }
    } catch (const std::exception& e) {
        result = oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error", "Invalid arguments: Failed to parse monitor.messages data value"}});
        m.respond(std::move(result), true);
        return;
    }

    if (not subs.empty())
        omq.update_monitors(subs, get_conn(m.scid()));

    m.respond(result);
}

void Endpoint::handle_request(std::string name, oxen::quic::message m, bool forwarded) {
    if (m.timed_out) {
        log::info(logcat, "Request (method:{}) timed out!");
        return;
    }

    std::string err;
    std::string params{m.body()};
    auto bt_encoded = !params.empty() && params.front() == 'd';

    // Check client rpc endpoints
    if (auto itr = rpc::RequestHandler::client_rpc_endpoints.find(name);
        itr != rpc::RequestHandler::client_rpc_endpoints.end()) {

        // This endpoint shouldn't have been registered if it isn't in here:
        assert(itr != rpc::RequestHandler::client_rpc_endpoints.end());

        try {
            itr->second.omq(
                    request_handler,
                    params,
                    forwarded,
                    [msg = std::move(m), bt_encoded](rpc::Response res) mutable {
                        std::string body;

                        if (auto* j = std::get_if<nlohmann::json>(&res.body)) {
                            nlohmann::json resp;

                            if (res.status != http::OK)
                                resp = nlohmann::json::array({res.status.first, std::move(*j)});
                            else
                                resp = std::move(*j);

                            if (bt_encoded)
                                body = bt_serialize(json_to_bt(std::move(resp)));
                            else
                                body = resp.dump();
                        } else
                            body = view_body(res);

                        std::string err;

                        if (res.status == http::OK)
                            err = fmt::format(
                                    "OMQ RPC request successful, returning {}-byte {} response",
                                    body.size(),
                                    body.empty() ? "text"
                                    : bt_encoded ? "bt-encoded"
                                                 : "json");
                        else
                            err = fmt::format(
                                    "OMQ RPC request failed, replying with [{}, {}]",
                                    res.status.first,
                                    body);

                        log::debug(logcat, err);
                        msg.respond(body, not(res.status == http::OK));
                    });
            return;
        } catch (const rpc::parse_error& p) {
            err = "Invalid request: {}"_format(p.what());
            log::info(logcat, err);
            err = serialize_error(BAD_REQUEST, std::move(err), bt_encoded);
        } catch (const std::exception& e) {
            err = "Client request raised an exception: {}"_format(e.what());
            log::info(logcat, err);
            err = serialize_error(INTERNAL_SERVER_ERROR, std::move(err), bt_encoded);
        }

        m.respond(err, true);
    }
}

}  // namespace oxenss::quic
