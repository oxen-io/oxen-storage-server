#include "omq_server.h"

#include "dev_sink.h"
#include "http.h"
#include "oxen_common.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "channel_encryption.hpp"
#include "oxenmq/connections.h"
#include "oxenmq/oxenmq.h"
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
        return fmt::format("tcp://{}:{}", sn->ip, sn->omq_port);

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
    // TODO: Just not returning any response here is gross: the protocol needs some way to return an
    // error state, but doesn't currently have one.
    if (!client_key) return;
    const auto& payload = message.data[1];

    request_handler_->process_proxy_exit(
        *client_key, payload,
        [send=message.send_later()](oxen::Response res) {
            OXEN_LOG(debug, "    Proxy exit status: {}", res.status.first);

            if (res.status == http::OK) {
                send.reply(res.body);
            } else {
                // We reply with 2 message parts which will be treated as
                // an error (rather than timeout)
                send.reply(std::to_string(res.status.first), res.body);
                OXEN_LOG(debug, "Error: status {} != OK for proxy_exit", res.status.first);
            }
        });
}

void OxenmqServer::handle_ping(oxenmq::Message& message) {
    OXEN_LOG(debug, "Remote pinged me");
    service_node_->update_last_ping(ReachType::OMQ);
    message.send_reply("pong");
}

void OxenmqServer::handle_onion_request(
        std::string_view payload,
        OnionRequestMetadata&& data,
        oxenmq::Message::DeferredSend send) {

    data.cb = [send](oxen::Response res) {
        if (OXEN_LOG_ENABLED(trace))
            OXEN_LOG(trace, "on response: {}...", to_string(res).substr(0, 100));

        send.reply(std::to_string(res.status.first), std::move(res).body);
    };

    if (data.hop_no > MAX_ONION_HOPS)
        return data.cb({http::BAD_REQUEST, "onion request max path length exceeded"});

    request_handler_->process_onion_req(payload, std::move(data));
}

void OxenmqServer::handle_onion_request(oxenmq::Message& message) {
    std::pair<std::string_view, OnionRequestMetadata> data;
    try {
        if (message.data.size() != 1)
            throw std::runtime_error{"expected 1 part, got " + std::to_string(message.data.size())};

        data = decode_onion_data(message.data[0]);
    } catch (const std::exception& e) {
        auto msg = "Invalid internal onion request: "s + e.what();
        OXEN_LOG(error, "{}", msg);
        message.send_reply(std::to_string(http::BAD_REQUEST.first), msg);
        return;
    }

    handle_onion_request(data.first, std::move(data.second), message.send_later());
}

void OxenmqServer::handle_onion_req_v2(oxenmq::Message& message) {

    OXEN_LOG(debug, "Got a v2 onion request over OxenMQ");

    constexpr int bad_code = http::BAD_REQUEST.first;
    if (message.data.size() != 2) {
        OXEN_LOG(error, "Expected 2 message parts, got {}",
                 message.data.size());
        message.send_reply(std::to_string(bad_code),
                "Incorrect number of onion request message parts");
        return;
    }

    auto eph_key = extract_x25519_from_hex(message.data[0]);
    if (!eph_key) {
        OXEN_LOG(error, "no ephemeral key in omq onion request");
        message.send_reply(std::to_string(bad_code), "Missing ephemeral key");
        return;
    }

    handle_onion_request(
            message.data[1], // ciphertext
            {*eph_key, nullptr, 1 /* hopno */, EncryptType::aes_gcm},
            message.send_later());
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

void omq_logger(oxenmq::LogLevel level, const char* file, int line,
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
        omq_logger,
        oxenmq::LogLevel::info}
{
    for (const auto& key : stats_access_keys)
        stats_access_keys_.emplace(key.view());

    OXEN_LOG(info, "OxenMQ is listenting on port {}", me.omq_port);

    omq_.listen_curve(
        fmt::format("tcp://0.0.0.0:{}", me.omq_port),
        [this](std::string_view /*addr*/, std::string_view pk, bool /*sn*/) {
            return stats_access_keys_.count(std::string{pk})
                ? oxenmq::AuthLevel::admin : oxenmq::AuthLevel::none;
        });

    // clang-format off
    omq_.add_category("sn", oxenmq::Access{oxenmq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("ping", [this](auto& m) { handle_ping(m); })
        // TODO: Backwards compat endpoint, can be removed after HF18:
        .add_request_command("onion_req", [this](auto& m) {
                if (m.data.size() == 1 && m.data[0] == "ping"sv)
                    return handle_ping(m);
                m.send_reply(
                    std::to_string(http::BAD_REQUEST.first),
                    "onion requests v1 not supported");
        })
        // TODO: Backwards compat, only used up until HF18
        .add_request_command("onion_req_v2", [this](auto& m) { handle_onion_req_v2(m); })
        .add_request_command("onion_request", [this](auto& m) { handle_onion_request(m); })
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

    // Be explicit about wanting per-SN unique connection IDs:
    omq_.EPHEMERAL_ROUTING_ID = true;
}

void OxenmqServer::connect_oxend(const oxenmq::address& oxend_rpc) {
    // Establish our persistent connection to oxend.
    oxend_conn_ = omq_.connect_remote(oxend_rpc,
        [this](auto&&) {
            OXEN_LOG(info, "connection to oxend established");
            service_node_->on_oxend_connected();
        },
        [this, oxend_rpc](auto&&, std::string_view reason) {
            OXEN_LOG(warn, "failed to connect to local oxend @ {}: {}; retrying", oxend_rpc, reason);
            connect_oxend(oxend_rpc);
        },
        // Turn this off since we are using oxenmq's own key and don't want to replace some existing
        // connection to it that might also be using that pubkey:
        oxenmq::connect_option::ephemeral_routing_id{},
        oxenmq::AuthLevel::admin);
}

void OxenmqServer::init(ServiceNode* sn, RequestHandler* rh, oxenmq::address oxend_rpc) {
    assert(!service_node_);
    service_node_ = sn;
    request_handler_ = rh;
    omq_.start();
    connect_oxend(oxend_rpc);
}

std::string OxenmqServer::encode_onion_data(std::string_view payload, const OnionRequestMetadata& data) {
    return oxenmq::bt_serialize<oxenmq::bt_dict>({
            {"data", payload},
            {"enc_type", to_string(data.enc_type)},
            {"ephemeral_key", data.ephem_key.view()},
            {"hop_no", data.hop_no},
    });
}

std::pair<std::string_view, OnionRequestMetadata> OxenmqServer::decode_onion_data(std::string_view data) {
    // NB: stream parsing here is alphabetical (that's also why these keys *aren't* constexprs: that
    // would potentially be error-prone if someone changed them without noticing the sort order
    // requirements).
    std::pair<std::string_view, OnionRequestMetadata> result;
    auto& [payload, meta] = result;
    oxenmq::bt_dict_consumer d{data};
    if (!d.skip_until("data"))
        throw std::runtime_error{"required data payload not found"};
    payload = d.consume_string_view();

    if (d.skip_until("enc_type"))
        meta.enc_type = parse_enc_type(d.consume_string_view());
    else
        meta.enc_type = EncryptType::aes_gcm;

    if (!d.skip_until("ephemeral_key"))
        throw std::runtime_error{"ephemeral key not found"};
    meta.ephem_key = x25519_pubkey::from_bytes(d.consume_string_view());

    if (d.skip_until("hop_no"))
        meta.hop_no = d.consume_integer<int>();
    if (meta.hop_no < 1)
        meta.hop_no = 1;

    return result;
}

} // namespace oxen
