#include "service_node.h"

#include "Database.hpp"
#include "Item.hpp"
#include "http_connection.h"
#include "https_client.h"
#include "lmq_server.h"
#include "loki_common.h"
#include "loki_logger.h"
#include "lokid_key.h"
#include "lokimq.h"
#include "net_stats.h"
#include "serialization.h"
#include "signature.h"
#include "utils.hpp"
#include "version.h"

#include "request_handler.h"

#include "dns_text_records.h"

#include <algorithm>
#include <chrono>
#include <fstream>

#include <boost/bind.hpp>

using json = nlohmann::json;
using loki::storage::Item;
using namespace std::chrono_literals;

namespace loki {
using http_server::connection_t;

using LockGuard = std::lock_guard<std::recursive_mutex>;

constexpr std::array<std::chrono::seconds, 8> RETRY_INTERVALS = {
    std::chrono::seconds(1),   std::chrono::seconds(5),
    std::chrono::seconds(10),  std::chrono::seconds(20),
    std::chrono::seconds(40),  std::chrono::seconds(80),
    std::chrono::seconds(160), std::chrono::seconds(320)};

constexpr std::chrono::milliseconds RELAY_INTERVAL = 350ms;

static void make_sn_request(boost::asio::io_context& ioc, const sn_record_t& sn,
                            const std::shared_ptr<request_t>& req,
                            http_callback_t&& cb) {
    // TODO: Return to using snode address instead of ip
    make_https_request(ioc, sn.ip(), sn.port(), sn.pub_key_base32z(), req,
                       std::move(cb));
}

FailedRequestHandler::FailedRequestHandler(
    boost::asio::io_context& ioc, const sn_record_t& sn,
    std::shared_ptr<request_t> req,
    boost::optional<std::function<void()>>&& give_up_cb)
    : ioc_(ioc), retry_timer_(ioc), sn_(sn), request_(std::move(req)),
      give_up_callback_(std::move(give_up_cb)) {}

void FailedRequestHandler::retry(std::shared_ptr<FailedRequestHandler>&& self) {

    attempt_count_ += 1;
    if (attempt_count_ > RETRY_INTERVALS.size()) {
        LOKI_LOG(debug, "Gave up after {} attempts", attempt_count_);
        if (give_up_callback_)
            (*give_up_callback_)();
        return;
    }

    retry_timer_.expires_after(RETRY_INTERVALS[attempt_count_ - 1]);
    LOKI_LOG(debug, "Will retry in {} secs",
             RETRY_INTERVALS[attempt_count_ - 1].count());

    retry_timer_.async_wait(
        [self = std::move(self)](const boost::system::error_code& ec) mutable {
            /// Save some references before possibly moved out of `self`
            const auto& sn = self->sn_;
            auto& ioc = self->ioc_;
            /// TODO: investigate whether we can get rid of the extra ptr copy
            /// here?
            const std::shared_ptr<request_t> req = self->request_;

            /// Request will be copied here
            make_sn_request(
                ioc, sn, req,
                [self = std::move(self)](sn_response_t&& res) mutable {
                    if (res.error_code != SNodeError::NO_ERROR) {
                        LOKI_LOG(debug, "Could not relay one: {} (attempt #{})",
                                 self->sn_, self->attempt_count_);
                        self->retry(std::move(self));
                    }
                });
        });
}

FailedRequestHandler::~FailedRequestHandler() {
    LOKI_LOG(trace, "~FailedRequestHandler()");
}

void FailedRequestHandler::init_timer() { retry(shared_from_this()); }

/// TODO: there should be config.h to store constants like these
#ifdef INTEGRATION_TEST
constexpr std::chrono::milliseconds SWARM_UPDATE_INTERVAL = 200ms;
#else
constexpr std::chrono::milliseconds SWARM_UPDATE_INTERVAL = 1000ms;
#endif
constexpr std::chrono::seconds STATS_CLEANUP_INTERVAL = 60min;
constexpr std::chrono::seconds PING_PEERS_INTERVAL = 10s;
constexpr std::chrono::minutes LOKID_PING_INTERVAL = 5min;
constexpr std::chrono::minutes POW_DIFFICULTY_UPDATE_INTERVAL = 10min;
constexpr std::chrono::seconds VERSION_CHECK_INTERVAL = 10min;
constexpr int CLIENT_RETRIEVE_MESSAGE_LIMIT = 10;

static std::shared_ptr<request_t> make_push_all_request(std::string&& data) {
    return build_post_request("/swarms/push_batch/v1", std::move(data));
}

static bool verify_message(const message_t& msg,
                           const std::vector<pow_difficulty_t> history,
                           const char** error_message = nullptr) {
    if (!util::validateTTL(msg.ttl)) {
        if (error_message)
            *error_message = "Provided TTL is not valid";
        return false;
    }
    if (!util::validateTimestamp(msg.timestamp, msg.ttl)) {
        if (error_message)
            *error_message = "Provided timestamp is not valid";
        return false;
    }
    std::string hash;
#ifndef DISABLE_POW
    const int difficulty =
        get_valid_difficulty(std::to_string(msg.timestamp), history);
    if (!checkPoW(msg.nonce, std::to_string(msg.timestamp),
                  std::to_string(msg.ttl), msg.pub_key, msg.data, hash,
                  difficulty)) {
        if (error_message)
            *error_message = "Provided PoW nonce is not valid";
        return false;
    }
#endif
    if (hash != msg.hash) {
        if (error_message)
            *error_message = "Incorrect hash provided";
        return false;
    }
    return true;
}

ServiceNode::ServiceNode(boost::asio::io_context& ioc,
                         boost::asio::io_context& worker_ioc, uint16_t port,
                         LokimqServer& lmq_server,
                         const lokid_key_pair_t& lokid_key_pair,
                         const std::string& db_location,
                         LokidClient& lokid_client, const bool force_start)
    : ioc_(ioc), worker_ioc_(worker_ioc),
      db_(std::make_unique<Database>(ioc, db_location)),
      swarm_update_timer_(ioc), lokid_ping_timer_(ioc),
      stats_cleanup_timer_(ioc), pow_update_timer_(worker_ioc),
      check_version_timer_(worker_ioc), peer_ping_timer_(ioc),
      relay_timer_(ioc), lokid_key_pair_(lokid_key_pair),
      lmq_server_(lmq_server), lokid_client_(lokid_client),
      force_start_(force_start) {

    char buf[64] = {0};
    if (!util::base32z_encode(lokid_key_pair_.public_key, buf)) {
        throw std::runtime_error("Could not encode our public key");
    }

    const std::string addr = buf;
    LOKI_LOG(info, "Our loki address: {}", addr);

    const auto pk_hex = util::as_hex(lokid_key_pair_.public_key);

    // TODO: get rid of "unused" fields
    our_address_ = sn_record_t(port, lmq_server.port(), addr, pk_hex, "unused",
                               "unused", "unused", "1.1.1.1");

    // TODO: fail hard if we can't encode our public key
    LOKI_LOG(info, "Read our snode address: {}", our_address_);
    swarm_ = std::make_unique<Swarm>(our_address_);

    LOKI_LOG(info, "Requesting initial swarm state");

#ifndef INTEGRATION_TEST
    bootstrap_data();
#else
    this->syncing_ = false;
#endif

    swarm_timer_tick();
    lokid_ping_timer_tick();
    cleanup_timer_tick();

#ifndef INTEGRATION_TEST
    ping_peers_tick();
#endif

    worker_thread_ = boost::thread([this]() { worker_ioc_.run(); });
    boost::asio::post(worker_ioc_, [this]() {
        pow_difficulty_timer_tick(std::bind(
            &ServiceNode::set_difficulty_history, this, std::placeholders::_1));
    });

    boost::asio::post(worker_ioc_,
                      [this]() { this->check_version_timer_tick(); });
}

static block_update_t
parse_swarm_update(const std::shared_ptr<std::string>& response_body) {

    if (!response_body) {
        LOKI_LOG(critical, "Bad lokid rpc response: no response body");
        throw std::runtime_error("Failed to parse swarm update");
    }
    const json body = json::parse(*response_body, nullptr, false);
    if (body.is_discarded()) {
        LOKI_LOG(trace, "Response body: {}", *response_body);
        LOKI_LOG(critical, "Bad lokid rpc response: invalid json");
        throw std::runtime_error("Failed to parse swarm update");
    }
    std::map<swarm_id_t, std::vector<sn_record_t>> swarm_map;
    block_update_t bu;

    LOKI_LOG(debug, "swarm repsonse: {}", *response_body);

    try {
        const auto& result = body.at("result");
        bu.height = result.at("height").get<uint64_t>();
        bu.block_hash = result.at("block_hash").get<std::string>();
        bu.hardfork = result.at("hardfork").get<int>();
        bu.unchanged =
            result.count("unchanged") && result.at("unchanged").get<bool>();
        if (bu.unchanged)
            return bu;

        const json service_node_states = result.at("service_node_states");

        for (const auto& sn_json : service_node_states) {
            const auto& pubkey =
                sn_json.at("service_node_pubkey").get_ref<const std::string&>();

            const swarm_id_t swarm_id =
                sn_json.at("swarm_id").get<swarm_id_t>();
            std::string snode_address = util::hex_to_base32z(pubkey);

            const uint16_t port = sn_json.at("storage_port").get<uint16_t>();
            const auto& snode_ip =
                sn_json.at("public_ip").get_ref<const std::string&>();

            const uint16_t lmq_port =
                sn_json.at("storage_lmq_port").get<uint16_t>();

            const auto& pubkey_x25519_hex =
                sn_json.at("pubkey_x25519").get_ref<const std::string&>();

            if (pubkey_x25519_hex.empty()) {
                LOKI_LOG(warn, "pubkey_x25519_hex is missing from sn info");
                continue;
            }

            // lokidKeyFromHex works for pub keys too
            const public_key_t pubkey_x25519 =
                lokidKeyFromHex(pubkey_x25519_hex);
            const std::string pubkey_x25519_bin = key_to_string(pubkey_x25519);

            const auto& pubkey_ed25519 =
                sn_json.at("pubkey_ed25519").get_ref<const std::string&>();

            if (pubkey_ed25519.empty()) {
                LOKI_LOG(warn, "pubkey_ed25519 is missing from sn info");
                continue;
            }

            const auto sn = sn_record_t{port,
                                        lmq_port,
                                        std::move(snode_address),
                                        pubkey,
                                        pubkey_x25519_hex,
                                        pubkey_x25519_bin,
                                        pubkey_ed25519,
                                        snode_ip};

            const bool fully_funded = sn_json.at("funded").get<bool>();

            /// We want to include (test) decommissioned nodes, but not
            /// partially funded ones.
            if (!fully_funded) {
                continue;
            }

            /// Storing decommissioned nodes (with dummy swarm id) in
            /// a separate data structure as it seems less error prone
            if (swarm_id == INVALID_SWARM_ID) {
                bu.decommissioned_nodes.push_back(sn);
            } else {
                swarm_map[swarm_id].push_back(sn);
            }
        }

    } catch (...) {
        LOKI_LOG(trace, "swarm repsonse: {}", body.dump(2));
        LOKI_LOG(critical, "Bad lokid rpc response: invalid json fields");
        throw std::runtime_error("Failed to parse swarm update");
    }

    for (auto const& swarm : swarm_map) {
        bu.swarms.emplace_back(SwarmInfo{swarm.first, swarm.second});
    }

    return bu;
}

void ServiceNode::bootstrap_data() {

    LockGuard guard(sn_mutex_);

    LOKI_LOG(trace, "Bootstrapping peer data");

    json params;
    json fields;

    fields["service_node_pubkey"] = true;
    fields["swarm_id"] = true;
    fields["storage_port"] = true;
    fields["public_ip"] = true;
    fields["height"] = true;
    fields["block_hash"] = true;
    fields["hardfork"] = true;
    fields["funded"] = true;
    fields["pubkey_x25519"] = true;
    fields["pubkey_ed25519"] = true;
    fields["storage_lmq_port"] = true;

    params["fields"] = fields;

    std::vector<std::pair<std::string, uint16_t>> seed_nodes;
    if (loki::is_mainnet()) {
        seed_nodes = {{{"public.loki.foundation", 38157},
                       {"storage.seed1.loki.network", 22023},
                       {"storage.seed2.loki.network", 38157},
                       {"imaginary.stream", 38157}}};
    } else {
        seed_nodes = {{{"public.loki.foundation", 38157},
                       {"storage.testnetseed1.loki.network", 38157}}};
    }

    auto req_counter = std::make_shared<int>(0);

    for (auto seed_node : seed_nodes) {
        lokid_client_.make_custom_lokid_request(
            seed_node.first, seed_node.second, "get_n_service_nodes", params,
            [this, seed_node, req_counter,
             node_count = seed_nodes.size()](const sn_response_t&& res) {
                if (res.error_code == SNodeError::NO_ERROR) {
                    try {
                        const block_update_t bu = parse_swarm_update(res.body);
                        // TODO: this should be disabled in the "testnet" mode
                        // (or changed to point to testnet seeds)
                        this->on_bootstrap_update(bu);
                    } catch (const std::exception& e) {
                        LOKI_LOG(
                            error,
                            "Exception caught while bootstrapping from {}: {}",
                            seed_node.first, e.what());
                    }
                } else {
                    LOKI_LOG(error, "Failed to contact bootstrap node {}",
                             seed_node.first);
                }

                (*req_counter)++;

                if (*req_counter == node_count && this->target_height_ == 0) {
                    // If target height is still 0 after having contacted
                    // (successfully or not) all seed nodes, just assume we have
                    // finished syncing. (Otherwise we will never get a chance
                    // to update syncing status.)
                    LOKI_LOG(
                        warn,
                        "Could not contact any of the seed nodes to get target "
                        "height. Going to assume our height is correct.");
                    this->syncing_ = false;
                }
            });
    }
}

bool ServiceNode::snode_ready(boost::optional<std::string&> reason) {

    LockGuard guard(sn_mutex_);

    bool ready = true;
    std::string buf;
    if (hardfork_ < STORAGE_SERVER_HARDFORK) {
        buf += "not yet on hardfork 12; ";
        ready = false;
    }
    if (!swarm_ || !swarm_->is_valid()) {
        buf += "not in any swarm; ";
        ready = false;
    }
    if (syncing_) {
        buf += "not done syncing; ";
        ready = false;
    }

    if (reason) {
        *reason = std::move(buf);
    }

    return ready || force_start_;
}

ServiceNode::~ServiceNode() {
    worker_ioc_.stop();
    worker_thread_.join();
};

static const char* method_to_str(ss_client::ReqMethod method, bool lmq) {

    if (lmq) {
        switch (method) {
        case ss_client::ReqMethod::DATA:
            return "sn.data";
        case ss_client::ReqMethod::PROXY_EXIT:
            return "sn.proxy_exit";
        case ss_client::ReqMethod::ONION_REQUEST:
            return "sn.onion_req";
        default:
            LOKI_LOG(critical, "UNKNOWN SS CLIENT METHOD");
            return "<invalid>";
        }
    } else {

        switch (method) {
        case ss_client::ReqMethod::DATA:
            return "/swarms/push_batch/v1";
        case ss_client::ReqMethod::PROXY_EXIT:
            return "/swarms/proxy_exit";
        case ss_client::ReqMethod::ONION_REQUEST:
            return "/onion_req";
        default:
            LOKI_LOG(critical, "UNKNOWN SS CLIENT METHOD");
            return "<invalid>";
        }
    }
}

void ServiceNode::send_onion_to_sn(const sn_record_t& sn,
                                   const std::string& payload,
                                   const std::string& eph_key,
                                   ss_client::Callback cb) const {

    // NO mutex needed (I think)

    lmq_server_.lmq()->request(sn.pubkey_x25519_bin(), "sn.onion_req",
                               std::move(cb), eph_key, payload);
}

// Calls callback on success only?
void ServiceNode::send_to_sn(const sn_record_t& sn, ss_client::ReqMethod method,
                             ss_client::Request req,
                             ss_client::Callback cb) const {

    LockGuard guard(sn_mutex_);

    const bool use_lmq = this->hardfork_ >= LOKIMQ_ONION_HARDFORK;

    const char* method_str = method_to_str(method, use_lmq);

    if (use_lmq) {
        // ===== make an lmq request =====

        LOKI_LOG(debug, "Going to use lokimq to send {} request to {}",
                 method_str, util::as_hex(sn.pubkey_x25519_bin()));

        // NOTE: this is ugly, but we will remove HTTP option in the next
        // release, and send_to_sn will probably go away with it.
        switch (method) {
        case ss_client::ReqMethod::DATA: {
            lmq_server_.lmq()->request(sn.pubkey_x25519_bin(), method_str,
                                       std::move(cb), req.body);
            break;
        }
        case ss_client::ReqMethod::PROXY_EXIT: {
            auto client_key = req.headers.find(LOKI_SENDER_KEY_HEADER);

            // I could just always assume that we are passing the right
            // parameters...
            if (client_key != req.headers.end()) {
                lmq_server_.lmq()->request(sn.pubkey_x25519_bin(), method_str,
                                           std::move(cb), client_key->second,
                                           req.body);
            } else {
                LOKI_LOG(debug, "Developer error: no {} passed in headers",
                         LOKI_SENDER_KEY_HEADER);
                // TODO: call cb?
                assert(false);
            }
            break;
        }
        }

    } else {
        // ===== make an https request =====

        LOKI_LOG(debug, "Going to use HTTP to send a request");

        auto http_req = build_post_request(method_str, std::move(req.body));
        // NOTE: we are not signing headers (why not?)
        this->sign_request(http_req);

        for (auto& header : req.headers) {
            LOKI_LOG(debug, "   - {}:{}", header.first, header.second);
            http_req->insert(header.first, header.second);
        }

        const bool needs_retrying =
            static_cast<bool>(method == ss_client::ReqMethod::DATA);

        // Note: often one of the reason for failure here is that the node has
        // just deregistered but our SN hasn't updated its swarm list yet.
        make_sn_request(
            ioc_, sn, http_req,
            [this, sn, http_req, cb, needs_retrying](sn_response_t&& res) {
                if (res.error_code != SNodeError::NO_ERROR) {

                    // TODO2: probably need a mutex here too

                    all_stats_.record_request_failed(sn);

                    if (res.error_code == SNodeError::NO_REACH) {
                        LOKI_LOG(debug,
                                 "Could not send to {} at first attempt: "
                                 "(Unreachable)",
                                 sn);
                    } else if (res.error_code == SNodeError::ERROR_OTHER) {
                        LOKI_LOG(debug,
                                 "Could send to {} at first attempt: "
                                 "(Generic error)",
                                 sn);
                    }

                    if (!needs_retrying) {
                        cb(false, {});
                        return;
                    }

                    std::function<void()> give_up_cb = [this, sn, cb]() {
                        LOKI_LOG(debug, "Failed to send a request to: {}", sn);
                        this->all_stats_.record_push_failed(sn);
                        cb(false, {});
                    };

                    boost::optional<std::function<void()>> gu_cb = give_up_cb;

                    // TODO: only retry if we are sending messages

                    // Not sure if we should use this for all http requests (or
                    // at all)
                    std::make_shared<FailedRequestHandler>(ioc_, sn, http_req,
                                                           std::move(gu_cb))
                        ->init_timer();
                } else {
                    LOKI_LOG(debug, "SN HTTP request is OK");

                    if (res.body) {
                        cb(true, {*res.body});
                    } else {
                        cb(true, {});
                    }
                }
            });
    }
}

void ServiceNode::relay_data_reliable(const std::string& blob,
                                      const sn_record_t& sn) const {

    auto reply_callback = [](bool success, std::vector<std::string> data) {
        if (!success) {
            LOKI_LOG(error, "Failed to send batch data: time-out");
        }
    };

    LOKI_LOG(debug, "Relaying data to: {}", sn);

    auto req = ss_client::Request{blob, {}};

    this->send_to_sn(sn, ss_client::ReqMethod::DATA, std::move(req),
                     reply_callback);
}

/// do this asynchronously on a different thread? (on the same thread?)
bool ServiceNode::process_store(const message_t& msg) {

    LockGuard guard(sn_mutex_);

    /// only accept a message if we are in a swarm
    if (!swarm_) {
        // This should never be printed now that we have "snode_ready"
        LOKI_LOG(error, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database
    this->save_if_new(msg);

    // Instead of sending the messages immediatly, store them in a buffer
    // and periodically send all messages from there as batches
    this->relay_buffer_.push_back(msg);

    return true;
}

void ServiceNode::save_if_new(const message_t& msg) {

    LockGuard guard(sn_mutex_);

    if (db_->store(msg.hash, msg.pub_key, msg.data, msg.ttl, msg.timestamp,
                   msg.nonce)) {
        LOKI_LOG(trace, "saved message: {}", msg.data);
    }
}

void ServiceNode::save_bulk(const std::vector<Item>& items) {

    LockGuard guard(sn_mutex_);

    if (!db_->bulk_store(items)) {
        LOKI_LOG(error, "failed to save batch to the database");
        return;
    }

    LOKI_LOG(trace, "saved messages count: {}", items.size());
}

void ServiceNode::on_bootstrap_update(const block_update_t& bu) {

    // Used in a callback to needs a mutex even if it is private
    LockGuard guard(sn_mutex_);

    swarm_->apply_swarm_changes(bu.swarms);
    target_height_ = std::max(target_height_, bu.height);
}

void ServiceNode::on_swarm_update(const block_update_t& bu) {

    // Used in a callback to needs a mutex even if it is private
    LockGuard guard(sn_mutex_);

    if (this->hardfork_ != bu.hardfork) {
        LOKI_LOG(debug, "New hardfork: {}", bu.hardfork);
        hardfork_ = bu.hardfork;
    }

    if (syncing_) {
        if (target_height_ == 0) {
            // If we are here, the probably means we were never able to contact
            // any seed, so the bast we can do is to assume we are synced
            // (this shouldn't be necessary as we do the same when all requests
            //  fail, but it won't hurt either)
            LOKI_LOG(info, "Target height is 0, assuming we are synced");

            syncing_ = false;
        } else {
            syncing_ = bu.height < target_height_;
        }
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        LOKI_LOG(debug, "Still syncing: {}/{}", bu.height, target_height_);
        // Note that because we are still syncing, we won't update our swarm id
        return;
    }

    if (bu.block_hash != block_hash_) {

        LOKI_LOG(debug, "new block, height: {}, hash: {}", bu.height,
                 bu.block_hash);

        if (bu.height > block_height_ + 1 && block_height_ != 0) {
            LOKI_LOG(warn, "Skipped some block(s), old: {} new: {}",
                     block_height_, bu.height);
            /// TODO: if we skipped a block, should we try to run peer tests for
            /// them as well?
        } else if (bu.height <= block_height_) {
            // TODO: investigate how testing will be affected under reorg
            LOKI_LOG(warn,
                     "new block height is not higher than the current height");
        }

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;

        block_hashes_cache_.push_back(std::make_pair(bu.height, bu.block_hash));

    } else {
        LOKI_LOG(trace, "already seen this block");
        return;
    }

    const SwarmEvents events = swarm_->derive_swarm_events(bu.swarms);

    swarm_->set_swarm_id(events.our_swarm_id);

    std::string reason;
    if (!this->snode_ready(boost::optional<std::string&>(reason))) {
        LOKI_LOG(warn, "Storage server is still not ready: {}", reason);
        return;
    } else {
        static bool active = false;
        if (!active) {
            LOKI_LOG(info, "Storage server is now active!");

            relay_timer_.expires_after(RELAY_INTERVAL);
            relay_timer_.async_wait(
                boost::bind(&ServiceNode::relay_buffered_messages, this));

            active = true;
        }
    }

    swarm_->update_state(bu.swarms, bu.decommissioned_nodes, events);

    if (!events.new_snodes.empty()) {
        bootstrap_peers(events.new_snodes);
    }

    if (!events.new_swarms.empty()) {
        bootstrap_swarms(events.new_swarms);
    }

    if (events.dissolved) {
        /// Go through all our PK and push them accordingly
        salvage_data();
    }

#ifndef INTEGRATION_TEST
    this->initiate_peer_test();
#endif
}

void ServiceNode::relay_buffered_messages() {

    LockGuard guard(sn_mutex_);

    // Should we wait for the response first?
    relay_timer_.expires_after(RELAY_INTERVAL);
    relay_timer_.async_wait(
        boost::bind(&ServiceNode::relay_buffered_messages, this));

    if (relay_buffer_.empty())
        return;

    LOKI_LOG(debug, "Relaying {} messages from buffer to {} nodes",
             relay_buffer_.size(), swarm_->other_nodes().size());

    this->relay_messages(relay_buffer_, swarm_->other_nodes());
    relay_buffer_.clear();
}

void ServiceNode::check_version_timer_tick() {

    check_version_timer_.expires_after(VERSION_CHECK_INTERVAL);
    check_version_timer_.async_wait(
        std::bind(&ServiceNode::check_version_timer_tick, this));

    dns::check_latest_version();
}

void ServiceNode::pow_difficulty_timer_tick(const pow_dns_callback_t cb) {
    std::error_code ec;
    std::vector<pow_difficulty_t> new_history = dns::query_pow_difficulty(ec);
    if (!ec) {
        boost::asio::post(ioc_, std::bind(cb, new_history));
    }
    pow_update_timer_.expires_after(POW_DIFFICULTY_UPDATE_INTERVAL);
    pow_update_timer_.async_wait(
        boost::bind(&ServiceNode::pow_difficulty_timer_tick, this, cb));
}

void ServiceNode::swarm_timer_tick() {

    LockGuard guard(sn_mutex_);

    LOKI_LOG(trace, "Swarm timer tick");

    json params;
    json fields;

    fields["service_node_pubkey"] = true;
    fields["swarm_id"] = true;
    fields["storage_port"] = true;
    fields["public_ip"] = true;
    fields["height"] = true;
    fields["block_hash"] = true;
    fields["hardfork"] = true;
    fields["funded"] = true;
    fields["pubkey_x25519"] = true;
    fields["pubkey_ed25519"] = true;
    fields["storage_lmq_port"] = true;

    params["fields"] = fields;
    params["poll_block_hash"] = block_hash_;

    params["active_only"] = false;

    lokid_client_.make_lokid_request(
        "get_n_service_nodes", params, [this](const sn_response_t&& res) {
            if (res.error_code == SNodeError::NO_ERROR) {
                try {
                    const block_update_t bu = parse_swarm_update(res.body);
                    if (!bu.unchanged)
                        on_swarm_update(bu);
                } catch (const std::exception& e) {
                    LOKI_LOG(error, "Exception caught on swarm update: {}",
                             e.what());
                }
            } else {
                LOKI_LOG(critical, "Failed to contact local Lokid");
            }

            // It would make more sense to wait the difference between the time
            // elapsed and SWARM_UPDATE_INTERVAL, but this is good enough:
            swarm_update_timer_.expires_after(SWARM_UPDATE_INTERVAL);
            swarm_update_timer_.async_wait(
                boost::bind(&ServiceNode::swarm_timer_tick, this));
        });
}

void ServiceNode::cleanup_timer_tick() {

    all_stats_.cleanup();

    stats_cleanup_timer_.expires_after(STATS_CLEANUP_INTERVAL);
    stats_cleanup_timer_.async_wait(
        boost::bind(&ServiceNode::cleanup_timer_tick, this));
}

void ServiceNode::ping_peers_tick() {

    // Used as a callback to needs a mutex even if it is private
    LockGuard guard(sn_mutex_);

    this->peer_ping_timer_.expires_after(PING_PEERS_INTERVAL);
    this->peer_ping_timer_.async_wait(
        std::bind(&ServiceNode::ping_peers_tick, this));

    /// TODO: To be safe, let's not even test peers until we
    /// have reached the right hardfork height
    if (hardfork_ < ENFORCED_REACHABILITY_HARDFORK) {
        LOKI_LOG(debug, "Have not reached HF13, skipping reachability tests");
        return;
    }

    /// We always test one node already known to be offline
    /// plus one random other node (could even be the same node)

    const auto random_node = swarm_->choose_funded_node();

    if (random_node) {

        if (random_node == our_address_) {
            LOKI_LOG(trace, "Would test our own node, skipping");
        } else {
            LOKI_LOG(trace, "Selected random node for testing: {}",
                     (*random_node).pub_key_hex());
            test_reachability(*random_node);
        }
    } else {
        LOKI_LOG(trace, "No nodes to test for reachability");
    }

    // TODO: there is an edge case where SS reported some offending
    // nodes, but then restarted, so SS won't give priority to those
    // nodes. SS will still test them eventually (through random selection) and
    // update Lokid, but this scenario could be made more robust.
    const auto offline_node = reach_records_.next_to_test();

    if (offline_node) {
        const boost::optional<sn_record_t> sn =
            swarm_->get_node_by_pk(*offline_node);
        LOKI_LOG(debug, "No offline nodes to test for reachability yet");
        if (sn) {
            test_reachability(*sn);
        } else {
            LOKI_LOG(debug, "Node does not seem to exist anymore: {}",
                     *offline_node);
            // delete its entry from test records as irrelevant
            reach_records_.expire(*offline_node);
        }
    }
}

void ServiceNode::sign_request(std::shared_ptr<request_t>& req) const {

    LockGuard guard(sn_mutex_);

    // TODO: investigate why we are not signing headers
    const auto hash = hash_data(req->body());
    const auto signature = generate_signature(hash, lokid_key_pair_);
    attach_signature(req, signature);
}

void ServiceNode::test_reachability(const sn_record_t& sn) {

    LOKI_LOG(debug, "Testing node for reachability {}", sn);

    auto callback = [this, sn](sn_response_t&& res) {
        this->process_reach_test_response(std::move(res), sn.pub_key_base32z());
    };

    nlohmann::json json_body;

    auto req = build_post_request("/swarms/ping_test/v1", json_body.dump());
    this->sign_request(req);

    make_sn_request(ioc_, sn, req, std::move(callback));
}

void ServiceNode::lokid_ping_timer_tick() {

    LockGuard guard(sn_mutex_);

    /// TODO: Note that this is not actually an SN response! (but Lokid)
    auto cb = [](const sn_response_t&& res) {
        if (res.error_code == SNodeError::NO_ERROR) {

            if (!res.body) {
                LOKI_LOG(critical, "Empty body on Lokid ping");
                return;
            }

            try {
                json res_json = json::parse(*res.body);

                const auto status =
                    res_json.at("result").at("status").get<std::string>();

                if (status == "OK") {
                    LOKI_LOG(info, "Successfully pinged Lokid");
                } else {
                    LOKI_LOG(critical, "Could not ping Lokid. Status: {}",
                             status);
                }
            } catch (...) {
                LOKI_LOG(critical,
                         "Could not ping Lokid: bad json in response");
            }

        } else {
            LOKI_LOG(critical, "Could not ping Lokid");
        }
    };

    json params;
    params["version_major"] = VERSION_MAJOR;
    params["version_minor"] = VERSION_MINOR;
    params["version_patch"] = VERSION_PATCH;
    params["storage_lmq_port"] = lmq_server_.port();

    lokid_client_.make_lokid_request("storage_server_ping", params,
                                     std::move(cb));

    lokid_ping_timer_.expires_after(LOKID_PING_INTERVAL);
    lokid_ping_timer_.async_wait(
        boost::bind(&ServiceNode::lokid_ping_timer_tick, this));
}

static std::vector<std::shared_ptr<request_t>>
make_batch_requests(std::vector<std::string>&& data) {

    std::vector<std::shared_ptr<request_t>> result;
    result.reserve(data.size());

    std::transform(std::make_move_iterator(data.begin()),
                   std::make_move_iterator(data.end()),
                   std::back_inserter(result), make_push_all_request);
    return result;
}

void ServiceNode::perform_blockchain_test(
    bc_test_params_t test_params,
    std::function<void(blockchain_test_answer_t)>&& cb) const {

    LockGuard guard(sn_mutex_);

    LOKI_LOG(debug, "Delegating blockchain test to Lokid");

    nlohmann::json params;

    params["max_height"] = test_params.max_height;
    params["seed"] = test_params.seed;

    auto on_resp = [cb = std::move(cb)](const sn_response_t& resp) {
        if (resp.error_code != SNodeError::NO_ERROR || !resp.body) {
            LOKI_LOG(critical, "Could not send blockchain request to Lokid");
            return;
        }

        const json body = json::parse(*resp.body, nullptr, false);

        if (body.is_discarded()) {
            LOKI_LOG(critical, "Bad Lokid rpc response: invalid json");
            return;
        }

        try {
            auto result = body.at("result");
            uint64_t height = result.at("res_height").get<uint64_t>();

            cb(blockchain_test_answer_t{height});

        } catch (...) {
        }
    };

    lokid_client_.make_lokid_request("perform_blockchain_test", params,
                                     std::move(on_resp));
}

void ServiceNode::attach_signature(std::shared_ptr<request_t>& request,
                                   const signature& sig) const {

    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());

    const std::string sig_b64 = util::base64_encode(raw_sig);
    request->set(LOKI_SNODE_SIGNATURE_HEADER, sig_b64);

    request->set(LOKI_SENDER_SNODE_PUBKEY_HEADER,
                 our_address_.pub_key_base32z());
}

void abort_if_integration_test() {
#ifdef INTEGRATION_TEST
    LOKI_LOG(critical, "ABORT in integration test");
    abort();
#endif
}

void ServiceNode::process_storage_test_response(const sn_record_t& testee,
                                                const Item& item,
                                                uint64_t test_height,
                                                sn_response_t&& res) {

    LockGuard guard(sn_mutex_);

    if (res.error_code != SNodeError::NO_ERROR) {
        // TODO: retry here, otherwise tests sometimes fail (when SN not
        // running yet)
        this->all_stats_.record_storage_test_result(testee, ResultType::OTHER);
        LOKI_LOG(debug, "Failed to send a storage test request to snode: {}",
                 testee);
        return;
    }

    // If we got here, the response is 200 OK, but we still need to check
    // status in response body and check the answer
    if (!res.body) {
        this->all_stats_.record_storage_test_result(testee, ResultType::OTHER);
        LOKI_LOG(debug, "Empty body in storage test response");
        return;
    }

    ResultType result = ResultType::OTHER;

    try {

        json res_json = json::parse(*res.body);

        const auto status = res_json.at("status").get<std::string>();

        if (status == "OK") {

            const auto value = res_json.at("value").get<std::string>();
            if (value == item.data) {
                LOKI_LOG(debug,
                         "Storage test is successful for: {} at height: {}",
                         testee, test_height);
                result = ResultType::OK;
            } else {
                LOKI_LOG(debug,
                         "Test answer doesn't match for: {} at height {}",
                         testee, test_height);
#ifdef INTEGRATION_TEST
                LOKI_LOG(warn, "got: {} expected: {}", value, item.data);
#endif
                result = ResultType::MISMATCH;
            }

        } else if (status == "wrong request") {
            LOKI_LOG(debug, "Storage test rejected by testee");
            result = ResultType::REJECTED;
        } else {
            result = ResultType::OTHER;
            LOKI_LOG(debug, "Storage test failed for some other reason");
        }
    } catch (...) {
        result = ResultType::OTHER;
        LOKI_LOG(debug, "Invalid json in storage test response");
    }

    this->all_stats_.record_storage_test_result(testee, result);
}

void ServiceNode::send_storage_test_req(const sn_record_t& testee,
                                        uint64_t test_height,
                                        const Item& item) {

    // Used as a callback to needs a mutex even if it is private
    LockGuard guard(sn_mutex_);

    nlohmann::json json_body;

    json_body["height"] = test_height;
    json_body["hash"] = item.hash;

    auto req = build_post_request("/swarms/storage_test/v1", json_body.dump());

    this->sign_request(req);

    make_sn_request(ioc_, testee, req,
                    [testee, item, height = this->block_height_,
                     this](sn_response_t&& res) {
                        this->process_storage_test_response(
                            testee, item, height, std::move(res));
                    });
}

void ServiceNode::send_blockchain_test_req(const sn_record_t& testee,
                                           bc_test_params_t params,
                                           uint64_t test_height,
                                           blockchain_test_answer_t answer) {

    // Used as a callback to needs a mutex even if it is private
    LockGuard guard(sn_mutex_);

    nlohmann::json json_body;

    json_body["max_height"] = params.max_height;
    json_body["seed"] = params.seed;
    json_body["height"] = test_height;

    auto req =
        build_post_request("/swarms/blockchain_test/v1", json_body.dump());
    this->sign_request(req);

    make_sn_request(ioc_, testee, req,
                    std::bind(&ServiceNode::process_blockchain_test_response,
                              this, std::placeholders::_1, answer, testee,
                              this->block_height_));
}

void ServiceNode::report_node_reachability(const sn_pub_key_t& sn_pk,
                                           bool reachable) {

    LockGuard guard(sn_mutex_);

    const auto sn = swarm_->get_node_by_pk(sn_pk);

    if (!sn) {
        LOKI_LOG(debug, "No Service node with pubkey: {}", sn_pk);
        return;
    }

    json params;
    params["type"] = "reachability";
    params["pubkey"] = (*sn).pub_key_hex();
    params["passed"] = reachable;

    /// Note that if Lokid restarts, all its reachability records will be
    /// updated to "true".

    auto cb = [this, sn_pk, reachable](const sn_response_t&& res) {
        if (res.error_code != SNodeError::NO_ERROR) {
            LOKI_LOG(warn, "Could not report node status");
            return;
        }

        if (!res.body) {
            LOKI_LOG(warn, "Empty body on Lokid report node status");
            return;
        }

        bool success = false;

        try {
            const json res_json = json::parse(*res.body);

            const auto status =
                res_json.at("result").at("status").get<std::string>();

            if (status == "OK") {
                success = true;
            } else {
                LOKI_LOG(warn, "Could not report node. Status: {}", status);
            }
        } catch (...) {
            LOKI_LOG(error,
                     "Could not report node status: bad json in response");
        }

        if (success) {
            if (reachable) {
                LOKI_LOG(debug, "Successfully reported node as reachable: {}",
                         sn_pk);
                this->reach_records_.expire(sn_pk);
            } else {
                LOKI_LOG(debug, "Successfully reported node as unreachable {}",
                         sn_pk);
                this->reach_records_.set_reported(sn_pk);
            }
        }
    };

    lokid_client_.make_lokid_request("report_peer_storage_server_status",
                                     params, std::move(cb));
}

void ServiceNode::process_reach_test_response(sn_response_t&& res,
                                              const sn_pub_key_t& pk) {

    LockGuard guard(sn_mutex_);

    if (res.error_code == SNodeError::NO_ERROR) {
        // NOTE: We don't need to report healthy nodes that previously has been
        // not been reported to Lokid as unreachable but I'm worried there might
        // be some race conditions, so do it anyway for now.
        this->report_node_reachability(pk, true);
        return;
    }

    const bool should_report = reach_records_.record_unreachable(pk);

    if (should_report) {
        this->report_node_reachability(pk, false);
    }
}

void ServiceNode::process_blockchain_test_response(
    sn_response_t&& res, blockchain_test_answer_t our_answer,
    sn_record_t testee, uint64_t bc_height) {

    LockGuard guard(sn_mutex_);

    LOKI_LOG(debug,
             "Processing blockchain test response from: {} at height: {}",
             testee, bc_height);

    ResultType result = ResultType::OTHER;

    if (res.error_code == SNodeError::NO_ERROR && res.body) {

        try {

            const json body = json::parse(*res.body, nullptr, true);
            uint64_t their_height = body.at("res_height").get<uint64_t>();

            if (our_answer.res_height == their_height) {
                result = ResultType::OK;
                LOKI_LOG(debug, "Success.");
            } else {
                result = ResultType::MISMATCH;
                LOKI_LOG(debug, "Failed: incorrect answer.");
            }

        } catch (...) {
            LOKI_LOG(debug, "Failed: could not find answer in json.");
        }

    } else {
        LOKI_LOG(debug, "Failed to send a blockchain test request to snode: {}",
                 testee);
    }

    this->all_stats_.record_blockchain_test_result(testee, result);
}

// Deterministically selects two random swarm members; returns true on success
bool ServiceNode::derive_tester_testee(uint64_t blk_height, sn_record_t& tester,
                                       sn_record_t& testee) {

    LockGuard guard(sn_mutex_);

    std::vector<sn_record_t> members = swarm_->other_nodes();
    members.push_back(our_address_);

    if (members.size() < 2) {
        LOKI_LOG(trace, "Could not initiate peer test: swarm too small");
        return false;
    }

    std::sort(members.begin(), members.end());

    std::string block_hash;
    if (blk_height == block_height_) {
        block_hash = block_hash_;
    } else if (blk_height < block_height_) {

        LOKI_LOG(trace, "got storage test request for an older block: {}/{}",
                 blk_height, block_height_);

        const auto it =
            std::find_if(block_hashes_cache_.begin(), block_hashes_cache_.end(),
                         [=](const std::pair<uint64_t, std::string>& val) {
                             return val.first == blk_height;
                         });

        if (it != block_hashes_cache_.end()) {
            block_hash = it->second;
        } else {
            LOKI_LOG(trace, "Could not find hash for a given block height");
            // TODO: request from lokid?
            return false;
        }
    } else {
        assert(false);
        LOKI_LOG(debug, "Could not find hash: block height is in the future");
        return false;
    }

    uint64_t seed;
    if (block_hash.size() < sizeof(seed)) {
        LOKI_LOG(error, "Could not initiate peer test: invalid block hash");
        return false;
    }

    std::memcpy(&seed, block_hash.data(), sizeof(seed));
    std::mt19937_64 mt(seed);
    const auto tester_idx =
        util::uniform_distribution_portable(mt, members.size());
    tester = members[tester_idx];

    uint64_t testee_idx;
    do {
        testee_idx = util::uniform_distribution_portable(mt, members.size());
    } while (testee_idx == tester_idx);

    testee = members[testee_idx];

    return true;
}

MessageTestStatus ServiceNode::process_storage_test_req(
    uint64_t blk_height, const std::string& tester_pk,
    const std::string& msg_hash, std::string& answer) {

    LockGuard guard(sn_mutex_);

    // 1. Check height, retry if we are behind
    std::string block_hash;

    if (blk_height > block_height_) {
        LOKI_LOG(debug, "Our blockchain is behind, height: {}, requested: {}",
                 block_height_, blk_height);
        return MessageTestStatus::RETRY;
    }

    // 2. Check tester/testee pair
    {
        sn_record_t tester;
        sn_record_t testee;
        this->derive_tester_testee(blk_height, tester, testee);

        if (testee != our_address_) {
            LOKI_LOG(error, "We are NOT the testee for height: {}", blk_height);
            return MessageTestStatus::WRONG_REQ;
        }

        if (tester.pub_key_base32z() != tester_pk) {
            LOKI_LOG(debug, "Wrong tester: {}, expected: {}", tester_pk,
                     tester.sn_address());
            abort_if_integration_test();
            return MessageTestStatus::WRONG_REQ;
        } else {
            LOKI_LOG(trace, "Tester is valid: {}", tester_pk);
        }
    }

    // 3. If for a current/past block, try to respond right away
    Item item;
    if (!db_->retrieve_by_hash(msg_hash, item)) {
        return MessageTestStatus::RETRY;
    }

    answer = item.data;
    return MessageTestStatus::SUCCESS;
}

bool ServiceNode::select_random_message(Item& item) {

    uint64_t message_count;
    if (!db_->get_message_count(message_count)) {
        LOKI_LOG(error, "Could not count messages in the database");
        return false;
    }

    LOKI_LOG(debug, "total messages: {}", message_count);

    if (message_count == 0) {
        LOKI_LOG(debug, "No messages in the database to initiate a peer test");
        return false;
    }

    // SNodes don't have to agree on this, rather they should use different
    // messages
    const auto msg_idx = util::uniform_distribution_portable(message_count);

    if (!db_->retrieve_by_index(msg_idx, item)) {
        LOKI_LOG(error, "Could not retrieve message by index: {}", msg_idx);
        return false;
    }

    return true;
}

void ServiceNode::initiate_peer_test() {

    LockGuard guard(sn_mutex_);

    // 1. Select the tester/testee pair
    sn_record_t tester, testee;

    /// We test based on the height a few blocks back to minimise discrepancies
    /// between nodes (we could also use checkpoints, but that is still not
    /// bulletproof: swarms are calculated based on the latest block, so they
    /// might be still different and thus derive different pairs)
    constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

    if (block_height_ < TEST_BLOCKS_BUFFER) {
        LOKI_LOG(debug, "Height {} is too small, skipping all tests",
                 block_height_);
        return;
    }

    const uint64_t test_height = block_height_ - TEST_BLOCKS_BUFFER;

    if (!this->derive_tester_testee(test_height, tester, testee)) {
        return;
    }

    LOKI_LOG(trace, "For height {}; tester: {} testee: {}", test_height, tester,
             testee);

    if (tester != our_address_) {
        /// Not our turn to initiate a test
        return;
    }

    /// 2. Storage Testing
    {
        // 2.1. Select a message
        Item item;
        if (!this->select_random_message(item)) {
            LOKI_LOG(debug, "Could not select a message for testing");
        } else {
            LOKI_LOG(trace, "Selected random message: {}, {}", item.hash,
                     item.data);

            // 2.2. Initiate testing request
            this->send_storage_test_req(testee, test_height, item);
        }
    }

    // Note: might consider choosing a different tester/testee pair for
    // different types of tests as to spread out the computations

    /// 3. Blockchain Testing
    {

        // Distance between two consecutive checkpoints,
        // should be in sync with lokid
        constexpr uint64_t CHECKPOINT_DISTANCE = 4;
        // We can be confident that blockchain data won't
        // change if we go this many blocks back
        constexpr uint64_t SAFETY_BUFFER_BLOCKS = CHECKPOINT_DISTANCE * 3;

        if (block_height_ <= SAFETY_BUFFER_BLOCKS) {
            LOKI_LOG(debug,
                     "Blockchain too short, skipping blockchain testing.");
            return;
        }

        bc_test_params_t params;
        params.max_height = block_height_ - SAFETY_BUFFER_BLOCKS;
        params.seed = util::rng()();

        auto callback =
            std::bind(&ServiceNode::send_blockchain_test_req, this, testee,
                      params, test_height, std::placeholders::_1);

        /// Compute your own answer, then initiate a test request
        this->perform_blockchain_test(params, callback);
    }
}

void ServiceNode::bootstrap_peers(const std::vector<sn_record_t>& peers) const {

    std::vector<Item> all_entries;
    this->get_all_messages(all_entries);

    this->relay_messages(all_entries, peers);
}

template <typename T>
std::string vec_to_string(const std::vector<T>& vec) {

    std::stringstream ss;

    ss << "[";

    for (auto i = 0u; i < vec.size(); ++i) {
        ss << vec[i];

        if (i < vec.size() - 1) {
            ss << " ";
        }
    }

    ss << "]";

    return ss.str();
}

void ServiceNode::bootstrap_swarms(
    const std::vector<swarm_id_t>& swarms) const {

    LockGuard guard(sn_mutex_);

    if (swarms.empty()) {
        LOKI_LOG(info, "Bootstrapping all swarms");
    } else {
        LOKI_LOG(info, "Bootstrapping swarms: {}", vec_to_string(swarms));
    }

    const auto& all_swarms = swarm_->all_valid_swarms();

    std::vector<Item> all_entries;
    if (!get_all_messages(all_entries)) {
        LOKI_LOG(error, "Could not retrieve entries from the database");
        return;
    }

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (auto i = 0u; i < all_swarms.size(); ++i) {
        swarm_id_to_idx.insert({all_swarms[i].swarm_id, i});
    }

    /// See what pubkeys we have
    std::unordered_map<std::string, swarm_id_t> cache;

    LOKI_LOG(debug, "We have {} messages", all_entries.size());

    std::unordered_map<swarm_id_t, std::vector<Item>> to_relay;

    for (auto& entry : all_entries) {

        swarm_id_t swarm_id;
        const auto it = cache.find(entry.pub_key);
        if (it == cache.end()) {

            bool success;
            auto pk = user_pubkey_t::create(entry.pub_key, success);

            if (!success) {
                LOKI_LOG(error, "Invalid pubkey in a message while "
                                "bootstrapping other nodes");
                continue;
            }

            swarm_id = get_swarm_by_pk(all_swarms, pk);
            cache.insert({entry.pub_key, swarm_id});
        } else {
            swarm_id = it->second;
        }

        bool relevant = false;
        for (const auto swarm : swarms) {

            if (swarm == swarm_id) {
                relevant = true;
            }
        }

        if (relevant || swarms.empty()) {

            to_relay[swarm_id].emplace_back(std::move(entry));
        }
    }

    LOKI_LOG(trace, "Bootstrapping {} swarms", to_relay.size());

    for (const auto& kv : to_relay) {
        const uint64_t swarm_id = kv.first;
        /// what if not found?
        const size_t idx = swarm_id_to_idx[swarm_id];

        relay_messages(kv.second, all_swarms[idx].snodes);
    }
}

template <typename Message>
void ServiceNode::relay_messages(const std::vector<Message>& messages,
                                 const std::vector<sn_record_t>& snodes) const {
    std::vector<std::string> batches = serialize_messages(messages);

    LOKI_LOG(debug, "Relayed messages:");
    for (auto msg : batches) {
        LOKI_LOG(debug, "    {}", msg);
    }
    LOKI_LOG(debug, "To Snodes:");
    for (auto sn : snodes) {
        LOKI_LOG(debug, "    {}", sn);
    }

    LOKI_LOG(debug, "Serialised batches: {}", batches.size());
    for (const sn_record_t& sn : snodes) {
        for (auto& batch : batches) {
            // TODO: I could probably avoid copying here
            this->relay_data_reliable(batch, sn);
        }
    }
}

void ServiceNode::salvage_data() const {

    /// This is very similar to ServiceNode::bootstrap_swarms, so just reuse it
    bootstrap_swarms({});
}

bool ServiceNode::retrieve(const std::string& pubKey,
                           const std::string& last_hash,
                           std::vector<Item>& items) {

    LockGuard guard(sn_mutex_);

    all_stats_.bump_retrieve_requests();

    return db_->retrieve(pubKey, items, last_hash,
                         CLIENT_RETRIEVE_MESSAGE_LIMIT);
}

void ServiceNode::set_difficulty_history(
    const std::vector<pow_difficulty_t>& new_history) {

    LockGuard guard(sn_mutex_);

    pow_history_ = new_history;
    for (const auto& difficulty : pow_history_) {
        if (curr_pow_difficulty_.timestamp < difficulty.timestamp) {
            curr_pow_difficulty_ = difficulty;
        }
    }
    LOKI_LOG(info, "Read PoW difficulty: {}", curr_pow_difficulty_.difficulty);
}

static void to_json(nlohmann::json& j, const test_result_t& val) {
    j["timestamp"] = val.timestamp;
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats_t& stats) {

    nlohmann::json json;

    json["total_store_requests"] = stats.get_total_store_requests();
    json["recent_store_requests"] = stats.get_recent_store_requests();
    json["previous_period_store_requests"] =
        stats.get_previous_period_store_requests();

    json["total_retrieve_requests"] = stats.get_total_retrieve_requests();
    json["recent_store_requests"] = stats.get_recent_store_requests();
    json["previous_period_retrieve_requests"] =
        stats.get_previous_period_retrieve_requests();

    json["reset_time"] = stats.get_reset_time();

    nlohmann::json peers;

    for (const auto& kv : stats.peer_report_) {
        const auto& pubkey = kv.first.pub_key_base32z();

        peers[pubkey]["requests_failed"] = kv.second.requests_failed;
        peers[pubkey]["pushes_failed"] = kv.second.requests_failed;
        peers[pubkey]["storage_tests"] = kv.second.storage_tests;
        peers[pubkey]["blockchain_tests"] = kv.second.blockchain_tests;
    }

    json["peers"] = peers;
    return json;
}

std::string ServiceNode::get_stats() const {

    LockGuard guard(sn_mutex_);

    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    uint64_t total_stored;
    if (db_->get_message_count(total_stored)) {
        val["total_stored"] = total_stored;
    }

    val["connections_in"] = get_net_stats().connections_in;
    val["http_connections_out"] = get_net_stats().http_connections_out;
    val["https_connections_out"] = get_net_stats().https_connections_out;
    val["open_socket_count"] = get_net_stats().open_fds.size();

    /// we want pretty (indented) json, but might change that in the future
    constexpr bool PRETTY = true;
    constexpr int indent = PRETTY ? 4 : 0;
    return val.dump(indent);
}

std::string ServiceNode::get_status_line() const {
    // This produces a short, single-line status string, used when running as a
    // systemd Type=notify service to update the service Status line.  The
    // status message has to be fairly short: has to fit on one line, and if
    // it's too long systemd just truncates it when displaying it.

    LockGuard guard(sn_mutex_);

    std::ostringstream s;
    s << 'v' << STORAGE_SERVER_VERSION_STRING;
    if (!loki::is_mainnet())
        s << " (TESTNET)";

    if (syncing_)
        s << "; SYNCING";
    s << "; sw=";
    if (!swarm_ || !swarm_->is_valid())
        s << "NONE";
    else {
        std::string swarm = std::to_string(swarm_->our_swarm_id());
        if (swarm.size() <= 6)
            s << swarm;
        else
            s << swarm.substr(0, 4) << u8"…" << swarm.back();
        s << "(n=" << (1 + swarm_->other_nodes().size()) << ")";
    }
    uint64_t total_stored;
    if (db_->get_message_count(total_stored))
        s << "; " << total_stored << " msgs";
    s << "; reqs(S/R): " << all_stats_.get_total_store_requests() << '/'
      << all_stats_.get_total_retrieve_requests();
    s << "; conns(in/http/https): " << get_net_stats().connections_in << '/'
      << get_net_stats().http_connections_out << '/'
      << get_net_stats().https_connections_out;
    return s.str();
}

int ServiceNode::get_curr_pow_difficulty() const {

    LockGuard guard(sn_mutex_);

    return curr_pow_difficulty_.difficulty;
}

bool ServiceNode::get_all_messages(std::vector<Item>& all_entries) const {

    LockGuard guard(sn_mutex_);

    LOKI_LOG(trace, "Get all messages");

    return db_->retrieve("", all_entries, "");
}

void ServiceNode::process_push_batch(const std::string& blob) {

    LockGuard guard(sn_mutex_);

    if (blob.empty())
        return;

    std::vector<message_t> messages = deserialize_messages(blob);

    LOKI_LOG(trace, "Saving all: begin");

    LOKI_LOG(debug, "Got {} messages from peers, size: {}", messages.size(),
             blob.size());

#ifndef DISABLE_POW
    const auto it = std::remove_if(
        messages.begin(), messages.end(), [this](const message_t& message) {
            return verify_message(message, pow_history_) == false;
        });
    messages.erase(it, messages.end());
    if (it != messages.end()) {
        LOKI_LOG(
            warn,
            "Some of the batch messages were removed due to incorrect PoW");
    }
#endif

    std::vector<Item> items;
    items.reserve(messages.size());

    // TODO: avoid copying m.data
    // Promoting message_t to Item:
    std::transform(messages.begin(), messages.end(), std::back_inserter(items),
                   [](const message_t& m) {
                       return Item{m.hash, m.pub_key,           m.timestamp,
                                   m.ttl,  m.timestamp + m.ttl, m.nonce,
                                   m.data};
                   });

    this->save_bulk(items);

    LOKI_LOG(trace, "Saving all: end");
}

bool ServiceNode::is_pubkey_for_us(const user_pubkey_t& pk) const {

    LockGuard guard(sn_mutex_);

    if (!swarm_) {
        LOKI_LOG(error, "Swarm data missing");
        return false;
    }
    return swarm_->is_pubkey_for_us(pk);
}

std::vector<sn_record_t>
ServiceNode::get_snodes_by_pk(const user_pubkey_t& pk) {

    LockGuard guard(sn_mutex_);

    if (!swarm_) {
        LOKI_LOG(error, "Swarm data missing");
        return {};
    }

    const auto& all_swarms = swarm_->all_valid_swarms();

    swarm_id_t swarm_id = get_swarm_by_pk(all_swarms, pk);

    // TODO: have get_swarm_by_pk return idx into all_swarms instead,
    // so we don't have to find it again

    for (const auto& si : all_swarms) {
        if (si.swarm_id == swarm_id)
            return si.snodes;
    }

    LOKI_LOG(critical, "Something went wrong in get_snodes_by_pk");

    return {};
}

bool ServiceNode::is_snode_address_known(const std::string& sn_address) {

    LockGuard guard(sn_mutex_);

    // TODO: need more robust handling of uninitialized swarm_
    if (!swarm_) {
        LOKI_LOG(error, "Swarm data missing");
        return false;
    }

    return swarm_->is_fully_funded_node(sn_address);
}

boost::optional<sn_record_t>
ServiceNode::find_node_by_x25519_bin(const sn_pub_key_t& pk) const {

    LockGuard guard(sn_mutex_);

    if (swarm_) {
        return swarm_->find_node_by_x25519_bin(pk);
    }

    return boost::none;
}

boost::optional<sn_record_t>
ServiceNode::find_node_by_ed25519_pk(const std::string& pk) const {

    LockGuard guard(sn_mutex_);

    if (swarm_) {
        return swarm_->find_node_by_ed25519_pk(pk);
    }

    return boost::none;
}

} // namespace loki
