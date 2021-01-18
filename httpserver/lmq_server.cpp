#include "lmq_server.h"

#include "dev_sink.h"
#include "oxen_common.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "request_handler.h"
#include "service_node.h"

#include <oxenmq/hex.h>
#include <oxenmq/oxenmq.h>
#include <nlohmann/json.hpp>

#include <optional>

namespace oxen {

std::string OxenmqServer::peer_lookup(std::string_view pubkey_bin) const {

    OXEN_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    std::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        OXEN_LOG(debug, "[LMQ] peer node not found {}!", pubkey_bin);
        return "";
    }
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

void OxenmqServer::handle_sn_proxy_exit(oxenmq::Message& message) {

    OXEN_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    OXEN_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    OXEN_LOG(debug, "[LMQ]   from: {}", oxenmq::to_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        OXEN_LOG(debug, "Expected 2 message parts, got {}",
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
        [this, origin_pk, reply_tag](oxen::Response res) {
            OXEN_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                this->oxenmq_->send(origin_pk, "REPLY", reply_tag,
                                    res.message());

            } else {
                // We reply with 2 messages which will be treated as
                // an error (rather than timeout)
                this->oxenmq_->send(origin_pk, "REPLY", reply_tag,
                                    fmt::format("{}", res.status()),
                                    res.message());
                OXEN_LOG(debug, "Error: status is not OK for proxy_exit: {}",
                         res.status());
            }
        });
}

void OxenmqServer::handle_onion_request(oxenmq::Message& message, bool v2) {

    OXEN_LOG(debug, "Got an onion request over OXENMQ");

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk,
                        reply_tag](oxen::Response res) mutable {
        OXEN_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

        std::string status = std::to_string(static_cast<int>(res.status()));

        oxenmq_->send(origin_pk, "REPLY", reply_tag, std::move(status),
                      res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to
        // avoid putting the error message in the log on 2.0.3+ nodes. (the
        // reply code here doesn't actually matter; the ping test only requires
        // that we provide *some* response).
        OXEN_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(ReachType::ZMQ);
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

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext),
                                        std::string(eph_key), on_response, v2);
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

void OxenmqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const oxend_key_pair_t& keypair,
                        const std::vector<std::string>& stats_access_keys) {

    using oxenmq::Allow;

    service_node_ = sn;
    request_handler_ = rh;

    for (const auto& key : stats_access_keys) {
        this->stats_access_keys.push_back(oxenmq::from_hex(key));
    }

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](oxenmq::LogLevel level, const char* file, int line,
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
        default:
            OXEN_LOG(debug, "[{}:{}]: {}", file, line, message);
        };
#undef LMQ_LOG_MAP
    };

    auto lookup_fn = [this](auto pk) { return this->peer_lookup(pk); };

    oxenmq_.reset(new OxenMQ{pubkey, seckey, true /* is service node */,
                             lookup_fn, logger});

    OXEN_LOG(info, "OxenMQ is listenting on port {}", port_);

    oxenmq_->log_level(oxenmq::LogLevel::info);
    // clang-format off
    oxenmq_->add_category("sn", oxenmq::Access{oxenmq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
        .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); })
        ;

    oxenmq_->add_category("service", oxenmq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

    // clang-format on
    oxenmq_->set_general_threads(1);

    oxenmq_->listen_curve(
        fmt::format("tcp://0.0.0.0:{}", port_),
        [this](std::string_view /*ip*/, std::string_view pk, bool /*sn*/) {
            const auto& keys = this->stats_access_keys;
            const auto it = std::find(keys.begin(), keys.end(), pk);
            return it == keys.end() ? oxenmq::AuthLevel::none
                                    : oxenmq::AuthLevel::admin;
        });

    oxenmq_->MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    oxenmq_->start();
}

OxenmqServer::OxenmqServer(uint16_t port) : port_(port){};
OxenmqServer::~OxenmqServer() = default;

} // namespace oxen
