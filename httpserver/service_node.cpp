#include "service_node.h"

#include "Database.hpp"
#include "Item.hpp"
#include "http_connection.h"
#include "lokid_key.h"
#include "pow.hpp"
#include "serialization.h"
#include "signature.h"
#include "utils.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>

#include <boost/beast/core/detail/base64.hpp>
#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>

using service_node::storage::Item;
using namespace std::chrono_literals;

namespace loki {
using http_server::connection_t;

constexpr std::array<std::chrono::seconds, 6> RETRY_INTERVALS = {
    std::chrono::seconds(1),  std::chrono::seconds(5),
    std::chrono::seconds(10), std::chrono::seconds(20),
    std::chrono::seconds(40), std::chrono::seconds(80)};

FailedRequestHandler::FailedRequestHandler(boost::asio::io_context& ioc,
                                           const sn_record_t& sn,
                                           std::shared_ptr<request_t> req)
    : ioc_(ioc), retry_timer_(ioc), sn_(sn), request_(std::move(req)) {}

void FailedRequestHandler::retry(std::shared_ptr<FailedRequestHandler>&& self) {

    attempt_count_ += 1;
    if (attempt_count_ > RETRY_INTERVALS.size()) {
        BOOST_LOG_TRIVIAL(debug)
            << "Gave up after " << attempt_count_ << " attempts";
        return;
    }

    retry_timer_.expires_after(RETRY_INTERVALS[attempt_count_ - 1]);
    BOOST_LOG_TRIVIAL(debug)
        << "Will retry in " << RETRY_INTERVALS[attempt_count_ - 1].count()
        << " secs";

    retry_timer_.async_wait(
        [self = std::move(self)](const boost::system::error_code& ec) mutable {
            /// Save some references before possibly moved out of `self`
            const auto& sn = self->sn_;
            auto& ioc = self->ioc_;
            /// TODO: investigate whether we can get rid of the extra ptr copy
            /// here?
            const std::shared_ptr<request_t> req = self->request_;

            /// Request will be copied here
            make_http_request(
                ioc, sn.address, sn.port, req,
                [self = std::move(self)](sn_response_t&& res) mutable {
                    if (res.error_code != SNodeError::NO_ERROR) {
                        BOOST_LOG_TRIVIAL(error)
                            << "Could not relay one: " << self->sn_
                            << " (attempt #" << self->attempt_count_ << ")";
                        /// TODO: record failure here as well?
                        self->retry(std::move(self));
                    }
                });
        });
}

FailedRequestHandler::~FailedRequestHandler() {
    BOOST_LOG_TRIVIAL(trace) << "~FailedRequestHandler()";
}

void FailedRequestHandler::init_timer() { retry(shared_from_this()); }

/// TODO: there should be config.h to store constants like these
constexpr std::chrono::milliseconds SWARM_UPDATE_INTERVAL = 200ms;

static std::shared_ptr<request_t> make_post_request(const char* target,
                                                    std::string&& data) {
    auto req = std::make_shared<request_t>();
    req->body() = std::move(data);
    req->method(http::verb::post);
    req->set(http::field::host, "service node");
    req->target(target);
    req->prepare_payload();
    return req;
}

static std::shared_ptr<request_t> make_push_all_request(std::string&& data) {
    return make_post_request("/v1/swarms/push_batch", std::move(data));
}

static std::shared_ptr<request_t> make_push_request(std::string&& data) {
    return make_post_request("/v1/swarms/push", std::move(data));
}

static bool verify_message(const message_t& msg, const char** error_message = nullptr) {
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
    if (!checkPoW(msg.nonce, std::to_string(msg.timestamp),
                  std::to_string(msg.ttl), msg.pub_key, msg.data, hash)) {
        if (error_message)
            *error_message = "Provided PoW nonce is not valid";
        return false;
    }
    if (hash != msg.hash) {
        if (error_message)
            *error_message = "Incorrect hash provided";
        return false;
    }
    return true;
}

ServiceNode::ServiceNode(boost::asio::io_context& ioc, uint16_t port,
                         const loki::lokid_key_pair_t& lokid_key_pair,
                         const std::string& db_location,
                         uint16_t lokid_rpc_port)
    : ioc_(ioc), db_(std::make_unique<Database>(ioc, db_location)),
      update_timer_(ioc), lokid_key_pair_(lokid_key_pair),
      lokid_rpc_port_(lokid_rpc_port) {

    char buf[64] = {0};
    if (char const* dest =
            util::base32z_encode(lokid_key_pair_.public_key, buf)) {
        our_address_.address = dest;
        our_address_.address.append(".snode");
    } else {
        throw std::runtime_error("Could not encode our public key");
    }
    // TODO: fail hard if we can't encode our public key
    BOOST_LOG_TRIVIAL(info) << "Read our snode address: " << our_address_;
    our_address_.port = port;

    swarm_timer_tick();
}

ServiceNode::~ServiceNode() = default;

void ServiceNode::send_sn_request(const std::shared_ptr<request_t>& req,
                             const sn_record_t& sn) const {

    BOOST_LOG_TRIVIAL(debug) << "Relaying data to: " << sn;

    // Note: often one of the reason for failure here is that the node has just
    // deregistered but our SN hasn't updated its swarm list yet.
    make_http_request(
        ioc_, sn.address, sn.port, req, [this, sn, req](sn_response_t&& res) {
            if (res.error_code != SNodeError::NO_ERROR) {
                snode_report_[sn].relay_fails += 1;

                if (res.error_code == SNodeError::NO_REACH) {
                    BOOST_LOG_TRIVIAL(error)
                        << "Could not relay data to: " << sn
                        << " (Unreachable)";
                } else if (res.error_code == SNodeError::ERROR_OTHER) {
                    BOOST_LOG_TRIVIAL(error)
                        << "Could not relay data to: " << sn
                        << " (Generic error)";
                }

                std::make_shared<FailedRequestHandler>(ioc_, sn, req)
                    ->init_timer();
            }
        });
}

void ServiceNode::register_listener(const std::string& pk,
                                    const std::shared_ptr<connection_t>& c) {
    pk_to_listeners[pk].push_back(c);
    BOOST_LOG_TRIVIAL(debug) << "register pubkey: " << pk
                             << ", total pubkeys: " << pk_to_listeners.size();
}

void ServiceNode::notify_listeners(const std::string& pk,
                                   const message_t& msg) {

    auto it = pk_to_listeners.find(pk);

    if (it != pk_to_listeners.end()) {

        auto& listeners = it->second;

        BOOST_LOG_TRIVIAL(debug)
            << "number of notified listeners: " << listeners.size();

        for (auto& c : listeners) {
            c->notify(msg);
        }
        pk_to_listeners.erase(it);
    }
}

void ServiceNode::reset_listeners() {

    /// It is probably not worth it to try to
    /// determine which connections needn't
    /// be reset (most of them will need to be),
    /// so we just reset all connections for
    /// simplicity
    for (auto& entry : pk_to_listeners) {
        for (auto& c : entry.second) {
            c->reset();
        }
    }

    pk_to_listeners.clear();
}

/// initiate a /swarms/push request
void ServiceNode::push_message(const message_t& msg) {

    if (!swarm_)
        return;

    const auto& others = swarm_->other_nodes();

    BOOST_LOG_TRIVIAL(debug)
        << "push_message to " << others.size() << " other nodes";

    std::string body;
    serialize_message(body, msg);

#ifndef DISABLE_SNODE_SIGNATURE
    const auto hash = hash_data(body);
    const auto signature = generate_signature(hash, lokid_key_pair_);
#endif

    auto req = make_push_request(std::move(body));

#ifndef DISABLE_SNODE_SIGNATURE
    attach_signature(req, signature);
#endif

    for (const auto& address : others) {
        /// send a request asynchronously
        send_sn_request(req, address);
    }
}

/// do this asynchronously on a different thread? (on the same thread?)
bool ServiceNode::process_store(const message_t& msg) {

    /// TODO: accept messages if they are coming from other service nodes

    /// only accept a message if we are in a swarm
    if (!swarm_) {
        BOOST_LOG_TRIVIAL(error) << "error: my swarm in not initialized";
        return false;
    }

    /// store to the database
    save_if_new(msg);

    /// initiate a /swarms/push request;
    /// (done asynchronously)
    this->push_message(msg);

    return true;
}

void ServiceNode::process_push(const message_t& msg) {
#ifndef DISABLE_POW
    const char* error_msg;
    if (!verify_message(msg, &error_msg))
        throw std::runtime_error(error_msg);
#endif
    save_if_new(msg);
}

void ServiceNode::save_if_new(const message_t& msg) {

    if (db_->store(msg.hash, msg.pub_key, msg.data, msg.ttl, msg.timestamp,
                   msg.nonce)) {
        notify_listeners(msg.pub_key, msg);
        BOOST_LOG_TRIVIAL(debug) << "saved message: " << msg.data;
    }
}

void ServiceNode::save_bulk(const std::vector<Item>& items) {

    if (!db_->bulk_store(items)) {
        BOOST_LOG_TRIVIAL(error) << "failed to save batch to the database";
        return;
    }

    BOOST_LOG_TRIVIAL(trace) << "saved messages count: " << items.size();

    // For batches, it is not trivial to get the list of saved (new)
    // messages, so we are only going to "notify" clients with no data
    // effectively resetting the connection.
    reset_listeners();
}

void ServiceNode::on_swarm_update(const block_update_t& bu) {
    if (!swarm_) {
        BOOST_LOG_TRIVIAL(info) << "Initialized our swarm";
        swarm_ = std::make_unique<Swarm>(our_address_);
    }

    if (bu.block_hash != block_hash_) {

        BOOST_LOG_TRIVIAL(debug)
            << boost::format("new block, height: %1%, hash: %2%") % bu.height %
                   bu.block_hash;

        if (bu.height > block_height_ + 1) {
            BOOST_LOG_TRIVIAL(warning)
                << "Skipped some block(s), old: " << block_height_
                << " new: " << bu.height;
            /// TODO: if we skipped a block, should we try to run peer tests for
            /// them as well?
        } else if (bu.height <= block_height_) {
            // TODO: investigate how testing will be affected under reorg
            BOOST_LOG_TRIVIAL(warning)
                << "new block height is not higher than the current height";
        }

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;

    } else {
        BOOST_LOG_TRIVIAL(trace) << "already seen this block";
        return;
    }

    const SwarmEvents events = swarm_->update_swarms(bu.swarms);

    if (!events.new_snodes.empty()) {
        bootstrap_peers(events.new_snodes);
    }

    if (!events.new_swarms.empty()) {
        bootstrap_swarms(events.new_swarms);
    }

    if (events.decommissioned) {
        /// Go through all our PK and push them accordingly
        salvage_data();
    }

    perform_peer_test();
}

void ServiceNode::swarm_timer_tick() {
    const swarm_callback_t cb =
        std::bind(&ServiceNode::on_swarm_update, this, std::placeholders::_1);
    request_swarm_update(ioc_, std::move(cb), lokid_rpc_port_);
    update_timer_.expires_after(SWARM_UPDATE_INTERVAL);
    update_timer_.async_wait(boost::bind(&ServiceNode::swarm_timer_tick, this));
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

void ServiceNode::attach_signature(std::shared_ptr<request_t>& request,
                                   const signature& sig) const {

    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());

    const std::string sig_b64 = boost::beast::detail::base64_encode(raw_sig);

    request->set(LOKI_SNODE_SIGNATURE_HEADER, sig_b64);

    // TODO: store both clean and .snode versions of the address
    std::string stripped = our_address_.address;
    size_t pos = stripped.find(".snode");
    if (pos != std::string::npos) {
        stripped.erase(pos);
    }
    request->set(LOKI_SENDER_SNODE_PUBKEY_HEADER, stripped);
}

void ServiceNode::perform_peer_test() {

    // 1. Select the tester/testee pair

    std::vector<sn_record_t> members_pk = swarm_->other_nodes();

    members_pk.push_back(our_address_);

    std::sort(members_pk.begin(), members_pk.end());

    if (members_pk.size() < 2) {
        BOOST_LOG_TRIVIAL(error)
            << "Could not initiate peer test: swarm too small";
        return;
    }

    uint64_t seed;
    if (block_hash_.size() < sizeof(seed)) {
        BOOST_LOG_TRIVIAL(error)
            << "Could not initiate peer test: invalid block hash";
        return;
    }

    std::memcpy(&seed, block_hash_.data(), sizeof(seed));
    std::mt19937_64 mt(seed);
    auto tester_idx =
        util::uniform_distribution_portable(mt, members_pk.size());
    sn_record_t tester = members_pk[tester_idx];
    std::cout << "     tester is: " << tester.port << std::endl;

    members_pk.erase(members_pk.begin() + tester_idx);
    auto testee_idx =
        util::uniform_distribution_portable(mt, members_pk.size());
    sn_record_t testee = members_pk[testee_idx];
    std::cout << "     testee is: " << testee.port << std::endl;

    if (tester == our_address_) {
        std::cout << "WE are the tester!\n";
    } else {
        // TODO: see if we are the testee
        return;
    }

    // 2. TODO: If we are the tester, send a test request to a testee
}

void ServiceNode::bootstrap_peers(const std::vector<sn_record_t>& peers) const {

    std::vector<Item> all_entries;
    db_->retrieve("", all_entries, "");

    relay_messages(all_entries, peers);
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

    if (swarms.empty()) {
        BOOST_LOG_TRIVIAL(info) << "bootstrapping all swarms\n";
    } else {
        BOOST_LOG_TRIVIAL(info)
            << "bootstrapping swarms: " << vec_to_string(swarms);
    }

    const auto& all_swarms = swarm_->all_swarms();

    std::vector<Item> all_entries;
    if (!db_->retrieve("", all_entries, "")) {
        BOOST_LOG_TRIVIAL(error)
            << "could not retrieve entries from the database\n";
        return;
    }

    std::unordered_map<swarm_id_t, size_t> swarm_id_to_idx;
    for (auto i = 0u; i < all_swarms.size(); ++i) {
        swarm_id_to_idx.insert({all_swarms[i].swarm_id, i});
    }

    /// See what pubkeys we have
    std::unordered_map<std::string, swarm_id_t> cache;

    BOOST_LOG_TRIVIAL(debug)
        << "we have " << all_entries.size() << " messages\n";

    std::unordered_map<swarm_id_t, std::vector<Item>> to_relay;

    for (auto& entry : all_entries) {

        swarm_id_t swarm_id;
        const auto it = cache.find(entry.pub_key);
        if (it == cache.end()) {
            swarm_id = get_swarm_by_pk(all_swarms, entry.pub_key);
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

    BOOST_LOG_TRIVIAL(trace)
        << "Bootstrapping " << to_relay.size() << " swarms";

    for (const auto& kv : to_relay) {
        const uint64_t swarm_id = kv.first;
        /// what if not found?
        const size_t idx = swarm_id_to_idx[swarm_id];

        relay_messages(kv.second, all_swarms[idx].snodes);
    }
}

void ServiceNode::relay_messages(
    const std::vector<service_node::storage::Item>& messages,
    const std::vector<sn_record_t>& snodes) const {
    std::vector<std::string> data = serialize_messages(messages);

#ifndef DISABLE_SNODE_SIGNATURE
    std::vector<signature> signatures;
    signatures.reserve(data.size());
    for (const auto& d : data) {
        const auto hash = hash_data(d);
        signatures.push_back(generate_signature(hash, lokid_key_pair_));
    }
#endif

    std::vector<std::shared_ptr<request_t>> batches =
        make_batch_requests(std::move(data));

#ifndef DISABLE_SNODE_SIGNATURE
    assert(batches.size() == signatures.size());
    for (size_t i = 0; i < batches.size(); ++i) {
        attach_signature(batches[i], signatures[i]);
    }
#endif

    BOOST_LOG_TRIVIAL(info) << "serialized batches: " << data.size();
    for (const sn_record_t& sn : snodes) {
        for (const std::shared_ptr<request_t>& batch : batches) {
            send_sn_request(batch, sn);
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
    return db_->retrieve(pubKey, items, last_hash);
}

bool ServiceNode::get_all_messages(std::vector<Item>& all_entries) {

    BOOST_LOG_TRIVIAL(trace) << "get all messages";

    return db_->retrieve("", all_entries, "");
}

void ServiceNode::process_push_batch(const std::string& blob) {
    // Note: we only receive batches on bootstrap (new swarm/new snode)

    if (blob.empty())
        return;

    std::vector<message_t> messages = deserialize_messages(blob);

    BOOST_LOG_TRIVIAL(trace) << "saving all: begin";

    BOOST_LOG_TRIVIAL(debug) << "got " << messages.size()
                             << " messages from peers, size: " << blob.size();

#ifndef DISABLE_POW
    const auto it = std::remove_if(messages.begin(), messages.end(),
                                   [](const message_t& message) {
                                       return verify_message(message) == false;
                                   });
    messages.erase(it, messages.end());
    if (it != messages.end()) {
        BOOST_LOG_TRIVIAL(warning)
            << "Some of the batch messages were removed due to incorrect PoW";
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

    save_bulk(items);

    BOOST_LOG_TRIVIAL(trace) << "saving all: end";
}

bool ServiceNode::is_pubkey_for_us(const std::string& pk) const {
    if (!swarm_) {
        BOOST_LOG_TRIVIAL(trace) << "swarm data missing";
        return false;
    }
    return swarm_->is_pubkey_for_us(pk);
}

std::vector<sn_record_t> ServiceNode::get_snodes_by_pk(const std::string& pk) {

    if (!swarm_) {
        BOOST_LOG_TRIVIAL(trace) << "swarm data missing";
        return {};
    }

    const auto& all_swarms = swarm_->all_swarms();

    swarm_id_t swarm_id = get_swarm_by_pk(all_swarms, pk);

    // TODO: have get_swarm_by_pk return idx into all_swarms instead,
    // so we don't have to find it again

    for (const auto& si : all_swarms) {
        if (si.swarm_id == swarm_id)
            return si.snodes;
    }

    BOOST_LOG_TRIVIAL(fatal) << "Something went wrong in get_snodes_by_pk";

    return {};
}

bool ServiceNode::is_snode_address_known(const std::string& sn_address) {

    // TODO: need more robust handling of uninitialized swarm_
    if (!swarm_) {
        BOOST_LOG_TRIVIAL(trace) << "swarm data missing";
        return {};
    }

    const auto& all_swarms = swarm_->all_swarms();

    return std::any_of(all_swarms.begin(), all_swarms.end(),
                       [&sn_address](const SwarmInfo& swarm_info) {
                           return std::any_of(
                               swarm_info.snodes.begin(),
                               swarm_info.snodes.end(),
                               [&sn_address](const sn_record_t& sn_record) {
                                   return sn_record.address == sn_address;
                               });
                       });
}

} // namespace loki
