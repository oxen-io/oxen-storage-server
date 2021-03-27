#include "lmq_server.h"

#include "dev_sink.h"
#include "oxen_common.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "oxenmq/connections.h"
#include "request_handler.h"
#include "service_node.h"

#include <oxenmq/hex.h>
#include <nlohmann/json.hpp>

#include <optional>

namespace oxen {

std::string OxenmqServer::peer_lookup(std::string_view pubkey_bin) const {

    OXEN_LOG(trace, "[LMQ] Peer Lookup");

    if (pubkey_bin.size() != sizeof(x25519_pubkey))
        return "";
    x25519_pubkey pubkey;
    std::memcpy(pubkey.data(), pubkey_bin.data(), sizeof(x25519_pubkey));

    if (auto sn = service_node_->find_node(pubkey))
        return fmt::format("tcp://{}:{}", sn->ip, sn->lmq_port);

    OXEN_LOG(debug, "[LMQ] peer node not found via x25519 pubkey {}!", pubkey);
    return "";
}

void OxenmqServer::handle_sn_data(oxenmq::Message& message) {

    OXEN_LOG(debug, "[LMQ] handle_sn_data");
    OXEN_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    OXEN_LOG(debug, "[LMQ]   from: {}", oxenmq::to_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    service_node_->process_push_batch(ss.str());

    OXEN_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending SN
    message.send_reply();
};

static std::optional<x25519_pubkey> extract_x25519_from_hex(std::string_view hex) {
    try {
        return x25519_pubkey::from_hex(hex);
    } catch (const std::exception& e) {
        OXEN_LOG(warn, "Failed to decode client key: {}", e.what());
    }
    return std::nullopt;
}

void OxenmqServer::handle_sn_proxy_exit(oxenmq::Message& message) {

    OXEN_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    OXEN_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    OXEN_LOG(debug, "[LMQ]   from: {}", oxenmq::to_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        OXEN_LOG(debug, "Expected 2 message parts, got {}",
                 message.data.size());
        return;
    }

    auto client_key = extract_x25519_from_hex(message.data[0]);
    if (!client_key) return;
    const auto& payload = message.data[1];

    request_handler_->process_proxy_exit(
        *client_key, payload,
        [send=message.send_later()](oxen::Response res) {
            OXEN_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                send.reply(res.message());
            } else {
                // We reply with 2 message parts which will be treated as
                // an error (rather than timeout)
                send.reply(fmt::format("{}", res.status()), res.message());
                OXEN_LOG(debug, "Error: status is not OK for proxy_exit: {}",
                         res.status());
            }
        });
}

void OxenmqServer::handle_onion_request(oxenmq::Message& message, bool v2) {

    OXEN_LOG(debug, "Got an onion request over OXENMQ");

    auto on_response = [send=message.send_later()](oxen::Response res) {
        OXEN_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

        std::string status = std::to_string(static_cast<int>(res.status()));

        send.reply(std::move(status), res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to
        // avoid putting the error message in the log on 2.0.3+ nodes. (the
        // reply code here doesn't actually matter; the ping test only requires
        // that we provide *some* response).
        OXEN_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(true /*omq*/);
        on_response(oxen::Response{Status::OK, "pong"});
        return;
    }

    if (message.data.size() != 2) {
        OXEN_LOG(error, "Expected 2 message parts, got {}",
                 message.data.size());
        on_response(oxen::Response{Status::BAD_REQUEST,
                                   "Incorrect number of messages"});
        return;
    }

    auto eph_key = extract_x25519_from_hex(message.data[0]);
    if (!eph_key) return;
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext),
                                        *eph_key, on_response, v2);
}

void OxenmqServer::handle_get_logs(oxenmq::Message& message) {

    OXEN_LOG(debug, "Received get_logs request via LMQ");

    auto dev_sink = dynamic_cast<oxen::dev_sink_mt*>(
        spdlog::get("oxen_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        OXEN_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        auto err_msg = "Developer error: sink #3 is not a dev sink.";
        message.send_reply(err_msg);
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    message.send_reply(val.dump(4));
}

void OxenmqServer::handle_get_stats(oxenmq::Message& message) {

    OXEN_LOG(debug, "Received get_stats request via LMQ");

    auto payload = service_node_->get_stats();

    message.send_reply(payload);
}

static void logger(oxenmq::LogLevel level, const char* file, int line,
        std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case oxenmq::LogLevel::LMQ_LVL:                                            \
        OXEN_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;

    switch (level) {
        LMQ_LOG_MAP(fatal, critical);
        LMQ_LOG_MAP(error, error);
        LMQ_LOG_MAP(warn, warn);
        LMQ_LOG_MAP(info, info);
        LMQ_LOG_MAP(trace, trace);
        LMQ_LOG_MAP(debug, debug);
    }
#undef LMQ_LOG_MAP
}

OxenmqServer::OxenmqServer(
        const sn_record_t& me,
        const x25519_seckey& privkey,
        const std::vector<x25519_pubkey>& stats_access_keys) :
    omq_{
        std::string{me.pubkey_x25519.view()},
        std::string{privkey.view()},
        true, // is service node
        [this](auto pk) { return peer_lookup(pk); }, // SN-by-key lookup func
        logger,
        oxenmq::LogLevel::info}
{
    for (const auto& key : stats_access_keys)
        stats_access_keys_.emplace(key.view());

    OXEN_LOG(info, "OxenMQ is listenting on port {}", me.lmq_port);

    omq_.listen_curve(
        fmt::format("tcp://0.0.0.0:{}", me.lmq_port),
        [this](std::string_view /*addr*/, std::string_view pk, bool /*sn*/) {
            return stats_access_keys_.count(std::string{pk})
                ? oxenmq::AuthLevel::admin : oxenmq::AuthLevel::none;
        });

    // clang-format off
    omq_.add_category("sn", oxenmq::Access{oxenmq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
        .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); })
        ;

    omq_.add_category("service", oxenmq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

    // We send a sub.block to oxend to tell it to push new block notifications to us via this
    // endpoint:
    omq_.add_category("notify", oxenmq::AuthLevel::admin)
        .add_request_command("block", [this](auto& m) {
            OXEN_LOG(debug, "Recieved new block notification from oxend, updating swarms");
            if (service_node_) service_node_->update_swarms();
        });

    // clang-format on
    omq_.set_general_threads(1);

    omq_.MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver)
}

void OxenmqServer::connect_oxend(const oxenmq::address& oxend_rpc) {
    // Establish our persistent connection to oxend.
    auto success = [this](auto&&) {
        OXEN_LOG(info, "connection to oxend established");
        service_node_->on_oxend_connected();
    };
    oxend_conn_ = omq_.connect_remote(oxend_rpc, success,
        [this, oxend_rpc](auto&&, std::string_view reason) {
            OXEN_LOG(warn, "failed to connect to local oxend @ {}: {}; retrying", oxend_rpc, reason);
            connect_oxend(oxend_rpc);
        },
        oxenmq::AuthLevel::admin);
}

void OxenmqServer::init(ServiceNode* sn, RequestHandler* rh, oxenmq::address oxend_rpc) {
    assert(!service_node_);
    service_node_ = sn;
    request_handler_ = rh;
    omq_.start();
    connect_oxend(oxend_rpc);
}

} // namespace oxen
