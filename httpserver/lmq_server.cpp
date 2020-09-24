#include "lmq_server.h"

#include "dev_sink.h"
#include "loki_common.h"
#include "loki_logger.h"
#include "lokid_key.h"
#include "request_handler.h"
#include "service_node.h"
#include "utils.hpp"

#include <lokimq/hex.h>
#include <lokimq/lokimq.h>

#include <optional>

namespace loki {

std::string LokimqServer::peer_lookup(std::string_view pubkey_bin) const {

    LOKI_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    std::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        LOKI_LOG(debug, "[LMQ] peer node not found {}!", pubkey_bin);
        return "";
    }
}

void LokimqServer::handle_sn_data(lokimq::Message& message) {

    LOKI_LOG(debug, "[LMQ] handle_sn_data");
    LOKI_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    LOKI_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    service_node_->process_push_batch(ss.str());

    LOKI_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending SN
    message.send_reply();
};

void LokimqServer::handle_sn_proxy_exit(lokimq::Message& message) {

    LOKI_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    LOKI_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    LOKI_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        LOKI_LOG(debug, "Expected 2 message parts, got {}",
                 message.data.size());
        return;
    }

    const auto& client_key = message.data[0];
    const auto& payload = message.data[1];

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    // TODO: accept string_view?
    request_handler_->process_proxy_exit(
        std::string(client_key), std::string(payload),
        [this, origin_pk, reply_tag](loki::Response res) {
            LOKI_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                this->lokimq_->send(origin_pk, "REPLY", reply_tag,
                                    res.message());

            } else {
                // We reply with 2 messages which will be treated as
                // an error (rather than timeout)
                this->lokimq_->send(origin_pk, "REPLY", reply_tag,
                                    fmt::format("{}", res.status()),
                                    res.message());
                LOKI_LOG(debug, "Error: status is not OK for proxy_exit: {}",
                         res.status());
            }
        });
}

void LokimqServer::handle_onion_request(lokimq::Message& message, bool v2) {

    LOKI_LOG(debug, "Got an onion request over LOKIMQ");

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk,
                        reply_tag](loki::Response res) mutable {
        LOKI_LOG(trace, "on response: {}", to_string(res));

        std::string status = std::to_string(static_cast<int>(res.status()));

        lokimq_->send(origin_pk, "REPLY", reply_tag, std::move(status),
                      res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to
        // avoid putting the error message in the log on 2.0.3+ nodes. (the
        // reply code here doesn't actually matter; the ping test only requires
        // that we provide *some* response).
        LOKI_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(ReachType::ZMQ);
        on_response(loki::Response{Status::OK, "pong"});
        return;
    }

    if (message.data.size() != 2) {
        LOKI_LOG(error, "Expected 2 message parts, got {}",
                 message.data.size());
        on_response(loki::Response{Status::BAD_REQUEST,
                                   "Incorrect number of messages"});
        return;
    }

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext),
                                        std::string(eph_key), on_response, v2);
}

bool LokimqServer::check_pn_server_pubkey(const std::string& pk) const {
    return pk == this->pn_server_key_;
}

void LokimqServer::handle_notify_add_pubkey(lokimq::Message& message) {

    if (!check_pn_server_pubkey(message.conn.pubkey())) {
        LOKI_LOG(debug,
                 "Attempt to use notify endpoint by unauthorised pubkey");
        return;
    }

    for (const auto& pubkey : message.data) {
        service_node_->add_notify_pubkey(message.conn, std::string(pubkey));
    }

    lokimq_->send(message.conn, "OK");
}

void LokimqServer::handle_notify_get_subscriber_count(
    lokimq::Message& message) {

    if (!check_pn_server_pubkey(message.conn.pubkey())) {
        LOKI_LOG(debug,
                 "Attempt to use notify endpoint by unauthorised pubkey");
        return;
    }

    const auto count = service_node_->get_notify_subscriber_count();

    lokimq_->send(message.conn, "COUNT", std::to_string(count));
}

void LokimqServer::handle_get_logs(lokimq::Message& message) {

    LOKI_LOG(debug, "Received get_logs request via LMQ");

    auto dev_sink = dynamic_cast<loki::dev_sink_mt*>(
        spdlog::get("loki_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        LOKI_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        auto err_msg = "Developer error: sink #3 is not a dev sink.";
        message.send_reply(err_msg);
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    message.send_reply(val.dump(4));
}

void LokimqServer::handle_get_stats(lokimq::Message& message) {

    LOKI_LOG(debug, "Received get_stats request via LMQ");

    auto payload = service_node_->get_stats();

    message.send_reply(payload);
}

void LokimqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const lokid_key_pair_t& keypair,
                        const std::vector<std::string>& stats_access_keys) {

    using lokimq::Allow;

    service_node_ = sn;
    request_handler_ = rh;

    // Push notification server's key
    this->pn_server_key_ = lokimq::from_hex(
        "BB88471D65E2659B30C55A5321CEBB5AAB2B70A398645C26DCA2B2FCB43FC518");

    for (const auto& key : stats_access_keys) {
        this->stats_access_keys.push_back(lokimq::from_hex(key));
    }

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](lokimq::LogLevel level, const char* file, int line,
                     std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case lokimq::LogLevel::LMQ_LVL:                                            \
        LOKI_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;
        switch (level) {
            LMQ_LOG_MAP(fatal, critical);
            LMQ_LOG_MAP(error, error);
            LMQ_LOG_MAP(warn, warn);
            LMQ_LOG_MAP(info, info);
            LMQ_LOG_MAP(trace, trace);
        default:
            LOKI_LOG(debug, "[{}:{}]: {}", file, line, message);
        };
#undef LMQ_LOG_MAP
    };

    auto lookup_fn = [this](auto pk) { return this->peer_lookup(pk); };

    lokimq_.reset(new LokiMQ{pubkey, seckey, true /* is service node */,
                             lookup_fn, logger});

    LOKI_LOG(info, "LokiMQ is listenting on port {}", port_);

    lokimq_->log_level(lokimq::LogLevel::info);
    // clang-format off
    lokimq_->add_category("sn", lokimq::Access{lokimq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
        .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); })
        ;

    lokimq_->add_category("notify", lokimq::AuthLevel::none)
        .add_command("add_pubkey", [this](auto& m) { this->handle_notify_add_pubkey(m); })
        .add_command("get_subscriber_count", [this](auto& m) { this->handle_notify_get_subscriber_count(m); });


    lokimq_->add_category("service", lokimq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

    // clang-format on
    lokimq_->set_general_threads(1);

    lokimq_->listen_curve(
        fmt::format("tcp://0.0.0.0:{}", port_),
        [this](std::string_view /*ip*/, std::string_view pk, bool /*sn*/) {
            const auto& keys = this->stats_access_keys;
            const auto it = std::find(keys.begin(), keys.end(), pk);
            return it == keys.end() ? lokimq::AuthLevel::none
                                    : lokimq::AuthLevel::admin;
        });

    lokimq_->MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    lokimq_->start();
}

LokimqServer::LokimqServer(uint16_t port) : port_(port){};
LokimqServer::~LokimqServer() = default;

} // namespace loki
