#include "omq_server.h"

#include "dev_sink.h"
#include "http.h"
#include "oxen_common.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "channel_encryption.hpp"
#include "rate_limiter.h"
#include "request_handler.h"
#include "service_node.h"

#include <nlohmann/json.hpp>
#include <oxenmq/hex.h>
#include <oxenmq/oxenmq.h>

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

void OxenmqServer::handle_ping(oxenmq::Message& message) {
    OXEN_LOG(debug, "Remote pinged me");
    service_node_->update_last_ping(ReachType::OMQ);
    message.send_reply("pong");
}

void OxenmqServer::handle_storage_test(oxenmq::Message& message) {
    if (message.conn.pubkey().size() != 32) {
        // This shouldn't happen as this endpoint should have remote-SN-only permissions, so be
        // noisy
        OXEN_LOG(err, "bug: invalid sn.storage_test omq request from {} with no pubkey",
                message.remote);
        return message.send_reply("invalid parameters");
    } else if (message.data.size() < 2) {
        OXEN_LOG(warn, "invalid sn.storage_test omq request from {}: not enough data parts; expected 2, received {}",
                message.remote, message.data.size());
        return message.send_reply("invalid parameters");
    }
    legacy_pubkey tester_pk;
    if (auto node = service_node_->find_node(x25519_pubkey::from_bytes(message.conn.pubkey()))) {
        tester_pk = node->pubkey_legacy;
        OXEN_LOG(debug, "incoming sn.storage_test request from {}@{}", tester_pk, message.remote);
    } else {
        OXEN_LOG(warn, "invalid sn.storage_test omq request from {}: sender is not an active SN");
        return message.send_reply("invalid pubkey");
    }

    uint64_t height;
    if (!util::parse_int(message.data[0], height) || !height) {
        OXEN_LOG(warn, "invalid sn.storage_test omq request from {}@{}: '{}' is not a valid height",
                tester_pk, message.remote, height);
        return message.send_reply("invalid height");
    }
    if (message.data[1].size() != 64) {
        OXEN_LOG(warn, "invalid sn.storage_test omq request from {}@{}: message hash is {} bytes, expected 64",
                tester_pk, message.remote, message.data[1].size());
        return message.send_reply("invalid msg hash");
    }

    request_handler_->process_storage_test_req(height, tester_pk, oxenmq::to_hex(message.data[1]),
            [reply=message.send_later()](MessageTestStatus status, std::string answer, std::chrono::steady_clock::duration elapsed) {
                switch (status) {
                    case MessageTestStatus::SUCCESS:
                        OXEN_LOG(debug, "Storage test success after {}", util::friendly_duration(elapsed));
                        reply.reply("OK", answer);
                        return;
                    case MessageTestStatus::WRONG_REQ:
                        reply.reply("wrong request");
                        return;
                    case MessageTestStatus::RETRY:
                        [[fallthrough]]; // If we're getting called then a retry ran out of time
                    case MessageTestStatus::ERROR:
                        // Promote this to `error` once we enforce storage testing
                        OXEN_LOG(debug, "Failed storage test, tried for {}", util::friendly_duration(elapsed));
                        reply.reply("other");
                }
            });
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
        OXEN_LOG(err, msg);
        message.send_reply(std::to_string(http::BAD_REQUEST.first), msg);
        return;
    }

    handle_onion_request(data.first, std::move(data.second), message.send_later());
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

void OxenmqServer::handle_client_request(std::string_view method, oxenmq::Message& message) {
    OXEN_LOG(debug, "Handling OMQ RPC request for {}", method);
    auto it = RequestHandler::client_rpc_endpoints.find(method);
    assert(it != RequestHandler::client_rpc_endpoints.end()); // This endpoint shouldn't have been registered if it isn't in here

    if (message.data.size() != 1) {
        OXEN_LOG(warn, "Invalid OMQ RPC request for {}: incorrect number of message parts ({})",
                method, message.data.size());
        message.send_reply(
                std::to_string(http::BAD_REQUEST.first),
                "Invalid request: expected 1 message part, received " + std::to_string(message.data.size()));
        return;
    }

    if (rate_limiter_->should_rate_limit_client(message.remote)) {
        OXEN_LOG(debug, "Rate limiting client request from {}", message.remote);
        return message.send_reply(std::to_string(http::TOO_MANY_REQUESTS.first), "Too many requests, try again later");
    }

    auto params = nlohmann::json::parse(message.data[0], nullptr, false);
    if (params.is_discarded()) {
        OXEN_LOG(debug, "Bad OMQ storage RPC request: invalid json");
        return message.send_reply(std::to_string(http::BAD_REQUEST.first), "invalid json");
    }

    it->second(*request_handler_, params, [send=message.send_later()](oxen::Response res) {
        if (res.status == http::OK) {
            OXEN_LOG(debug, "OMQ RPC request successful, returning {}-byte response", res.body.size());
            // Success: return just the body
            send.reply(std::move(res.body));
        } else {
            // On error return [errcode, body]
            OXEN_LOG(debug, "OMQ RPC request failed, replying with [{}, {}]", res.status.first, res.body);
            send.reply(std::to_string(res.status.first), res.body);
        }
    });
}

void omq_logger(oxenmq::LogLevel level, const char* file, int line,
        std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case oxenmq::LogLevel::LMQ_LVL:                                            \
        OXEN_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;

    switch (level) {
        LMQ_LOG_MAP(fatal, critical);
        LMQ_LOG_MAP(error, err);
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

    // Endpoints invoked by other SNs
    omq_.add_category("sn", oxenmq::Access{oxenmq::AuthLevel::none, true, false}, 2 /*reserved threads*/, 1000 /*max queue*/)
        .add_request_command("data", [this](auto& m) { handle_sn_data(m); })
        .add_request_command("ping", [this](auto& m) { handle_ping(m); })
        .add_request_command("storage_test", [this](auto& m) { handle_storage_test(m); }) // NB: requires a 60s request timeout
        .add_request_command("onion_request", [this](auto& m) { handle_onion_request(m); })
        ;

    // storage.WHATEVER (e.g. storage.store, storage.retrieve, etc.) endpoints are invokable by
    // anyone (i.e. clients).  These endpoints return a single-part message [body] on success, or a
    // two-part message [errcode, body] on error.
    auto st_cat = omq_.add_category("storage", oxenmq::AuthLevel::none, 1 /*reserved threads*/, 200 /*max queue*/);
    for (const auto& [name, _cb] : RequestHandler::client_rpc_endpoints)
        st_cat.add_request_command(std::string{name}, [this, name=name](auto& m) { handle_client_request(name, m); });

    // Endpoints invokable by a local admin
    omq_.add_category("service", oxenmq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { handle_get_logs(m); })
        ;

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
        10 * 1024 * 1024; // 10 MB (needed by the fileserver, and swarm msg serialization)

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

void OxenmqServer::init(ServiceNode* sn, RequestHandler* rh, RateLimiter* rl, oxenmq::address oxend_rpc) {
    assert(!service_node_);
    service_node_ = sn;
    request_handler_ = rh;
    rate_limiter_ = rl;
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
