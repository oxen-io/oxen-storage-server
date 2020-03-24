#include "lmq_server.h"

#include "loki_common.h"
#include "loki_logger.h"
#include "lokid_key.h"
#include "service_node.h"
#include "request_handler.h"
#include "utils.hpp"

#include <lokimq/lokimq.h>

namespace loki {

std::string LokimqServer::peer_lookup(lokimq::string_view pubkey_bin) const {

    LOKI_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    boost::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        LOKI_LOG(debug, "[LMQ] peer node not found!");
        return "";
    }
}

lokimq::Allow
LokimqServer::auth_level_lookup(lokimq::string_view ip,
                                lokimq::string_view pubkey) const {

    LOKI_LOG(debug, "[LMQ] Auth Level Lookup");

    // TODO: make SN accept string_view
    boost::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey));

    bool is_sn = sn ? true : false;

    LOKI_LOG(debug, "[LMQ]    is service node: {}", is_sn);

    return lokimq::Allow{lokimq::AuthLevel::none, is_sn};
};

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

    // TODO: accept string_view?
    auto res = request_handler_->process_proxy_exit(std::string(client_key), std::string(payload));

    if (res.status() == Status::OK) {

        // TODO: we might want to delay reponding in the case of LP,
        // unless the proxy delay is long enough

        message.send_reply(res.message());

    } else {
        // TODO: better handle this (unlikely) error
        LOKI_LOG(debug, "Error: status is not OK for proxy_exit");
    }

}

void LokimqServer::handle_onion_request(lokimq::Message& message) {

    LOKI_LOG(debug, "Got an onion request over LOKIMQ");

    auto &reply_tag = message.reply_tag;
    auto &origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk, reply_tag](loki::Response res) mutable {
        LOKI_LOG(debug, "on response: {}", to_string(res));

        std::string status = std::to_string(static_cast<int>(res.status()));

        lokimq_->send(origin_pk, "REPLY", reply_tag, std::move(status), res.message());
    };

    if (message.data.size() != 2) {
        LOKI_LOG(error, "Expected 2 message parts, got {}", message.data.size());
        on_response(loki::Response{Status::BAD_REQUEST, "Incorrect number of messages"});
        return;
    }

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext), std::string(eph_key), on_response);
}

void LokimqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const lokid_key_pair_t& keypair) {

    namespace ph = std::placeholders;
    using lokimq::Allow;
    using lokimq::string_view;

    service_node_ = sn;
    request_handler_ = rh;

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](lokimq::LogLevel level, const char* file, int line,
                     std::string message) {
        LOKI_LOG(debug, "[line: {}]: {}", line, message);
    };

    auto lookup_fn = std::bind(&LokimqServer::peer_lookup, this, ph::_1);

    auto allow_fn =
        std::bind(&LokimqServer::auth_level_lookup, this, ph::_1, ph::_2);

    lokimq_.reset(new LokiMQ{pubkey,
                             seckey,
                             true /* is service node */,
                             lookup_fn,
                             logger});

    LOKI_LOG(info, "LokiMQ is listenting on port {}", port_);

    lokimq_->add_category("sn",
                          lokimq::Access{lokimq::AuthLevel::none, true, false});

    lokimq_->log_level(lokimq::LogLevel::warn);

    // ============= COMMANDS - BEGIN =============

    lokimq_->add_request_command(
        "sn", "data", std::bind(&LokimqServer::handle_sn_data, this, ph::_1));

    lokimq_->add_request_command(
        "sn", "proxy_exit",
        std::bind(&LokimqServer::handle_sn_proxy_exit, this, ph::_1));

    lokimq_->add_request_command(
        "sn", "onion_req",
        std::bind(&LokimqServer::handle_onion_request, this, ph::_1));

    // +============= COMMANDS - END ==============

    lokimq_->set_general_threads(1);

    lokimq_->listen_curve(fmt::format("tcp://0.0.0.0:{}", port_), allow_fn);

    lokimq_->MAX_MSG_SIZE = 10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    lokimq_->start();
}

LokimqServer::LokimqServer(uint16_t port) : port_(port){};
LokimqServer::~LokimqServer() = default;

} // namespace loki