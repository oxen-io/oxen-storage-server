#include "service_node.h"

#include "serialization.h"
#include "sn_test.h"
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <oxenmq/connections.h>
#include <oxen/quic/format.hpp>
#include <oxenss/version.h>
#include <oxenss/common/mainnet.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/base.h>
#include <oxenss/server/omq.h>
#include <oxenss/logging/oxen_logger.h>
#include <iterator>
#include <numeric>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/random.hpp>

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>

#include <algorithm>
#include <tuple>
#include <utility>

using json = nlohmann::json;

namespace oxenss::snode {

static auto logcat = log::Cat("snode");

// Threshold of missing data records at which we start warning and consult bootstrap nodes
// (mainly so that we don't bother producing warning spam or going to the bootstrap just for a
// few new nodes that will often have missing info for a few minutes).
using MISSING_PUBKEY_THRESHOLD = std::ratio<3, 100>;

/// TODO: there should be config.h to store constants like these
constexpr auto OXEND_PING_INTERVAL = 30s;

// How often to trigger 'check_new_members' which checks for 'data ready' handshakes from
// swarm members and propagate a DB dump if necessary.
constexpr auto NEW_SWARM_MEMBER_INTERVAL = 10s;

struct SerialiseRetryableRequestsResult {
    SerialiseBTResult bt;
    std::vector<RequestRetry> retryable_requests;
};

SerialiseDataReadyRequestResult serialise_data_ready_request(
        Serialise serialise, std::string_view read_data, const DataReadyRequest& write_data) {
    SerialiseDataReadyRequestResult result = {};
    uint32_t version = 0;
    constexpr std::string_view VERSION_KEY = "@";
    constexpr std::string_view STATUS_KEY = "s";
    constexpr std::string_view NEED_DB_DUMP_KEY = "t";
    static_assert(VERSION_KEY < STATUS_KEY);
    static_assert(STATUS_KEY < NEED_DB_DUMP_KEY);

    if (serialise == Serialise::Write) {
        oxenc::bt_dict_producer d;
        d.append(VERSION_KEY, version);
        d.append(NEED_DB_DUMP_KEY, write_data.needs_db_dump);
        result.bt.write_payload = d.view();
        result.bt.success = result.bt.error.empty();
    } else {
        if (read_data.size()) {
            oxenc::bt_dict_consumer d{read_data};
            try {
                version = d.require<uint8_t>(VERSION_KEY);
            } catch (const std::exception& e) {
                result.bt.error =
                        "Failed to parse sn data ready request version: {}"_format(e.what());
            }

            if (result.bt.error.empty()) {
                try {
                    result.request.needs_db_dump = d.require<bool>(NEED_DB_DUMP_KEY);
                } catch (const std::exception& e) {
                    result.bt.error =
                            "Failed to parse sn data ready db dump flag: {}"_format(e.what());
                }
            }
        } else {
            result.bt.error = "Failed to parse data ready payload: no bytes given";
        }

        result.bt.success = result.bt.error.empty();
    }
    return result;
}

static SerialiseRetryableRequestsResult serialize_retryable_requests(
        Serialise serialise, std::string_view read_data, std::span<RequestRetry> write_data) {
    SerialiseRetryableRequestsResult result = {};
    uint32_t version = 0;

    constexpr std::string_view VERSION_KEY = "@";
    constexpr std::string_view RETRYABLE_REQUESTS_KEY = "r";
    assert(VERSION_KEY < RETRYABLE_REQUESTS_KEY);

    // Retryable request keys
    constexpr std::string_view COMMAND_KEY = "c";
    constexpr std::string_view REQ_PAYLOAD_KEY = "r";
    constexpr std::string_view CREATE_TIME_KEY = "t";
    constexpr std::string_view NODES_KEY = "u";
    assert(COMMAND_KEY < REQ_PAYLOAD_KEY);
    assert(REQ_PAYLOAD_KEY < CREATE_TIME_KEY);
    assert(CREATE_TIME_KEY < NODES_KEY);

    // Retrayble request entry keys
    constexpr std::string_view KEY_KEY = "i";
    constexpr std::string_view DEADLINE_KEY = "l";
    constexpr std::string_view NEXT_RETRY_DELAY_KEY = "n";
    constexpr std::string_view REASON_KEY = "r";
    assert(KEY_KEY < DEADLINE_KEY);
    assert(DEADLINE_KEY < NEXT_RETRY_DELAY_KEY);
    assert(NEXT_RETRY_DELAY_KEY < REASON_KEY);

    if (serialise == Serialise::Write) {
        oxenc::bt_dict_producer d;
        d.append(VERSION_KEY, version);

        oxenc::bt_list_producer retry_list = d.append_list(RETRYABLE_REQUESTS_KEY);
        for (const auto& it : write_data) {
            oxenc::bt_dict_producer retry_dict = retry_list.append_dict();
            retry_dict.append(COMMAND_KEY, it.cmd);
            retry_dict.append(REQ_PAYLOAD_KEY, it.req_payload);
            uint64_t create_time_u64 = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               it.create_time.time_since_epoch())
                                               .count();
            retry_dict.append(CREATE_TIME_KEY, create_time_u64);
            oxenc::bt_list_producer node_list = retry_dict.append_list(NODES_KEY);
            for (const auto& node_it : it.nodes) {
                oxenc::bt_dict_producer node_dict = node_list.append_dict();
                uint32_t reason_u32 = static_cast<uint32_t>(node_it.reason);
                uint64_t deadline_u64 = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                node_it.deadline.time_since_epoch())
                                                .count();
                uint64_t next_retry_delay_u64 = node_it.next_retry_delay.count();
                node_dict.append(KEY_KEY, node_it.key);
                node_dict.append(DEADLINE_KEY, deadline_u64);
                node_dict.append(NEXT_RETRY_DELAY_KEY, next_retry_delay_u64);
                node_dict.append(REASON_KEY, reason_u32);
            }
        }

        result.bt.success = true;
        result.bt.write_payload = d.view();
    } else {
        if (read_data.size()) {
            oxenc::bt_dict_consumer d{read_data};
            try {
                version = d.require<uint8_t>(VERSION_KEY);
            } catch (const std::exception& e) {
                result.bt.error = "Failed to parse retryable request version: {}"_format(e.what());
            }

            if (version != 0)
                result.bt.error =
                        "Unrecognised retryable request version: {}, skipping"_format(version);

            if (result.bt.error.empty()) {
                // Initially a dummy list that we will std::move the real list into
                oxenc::bt_list_consumer retry_list("l");
                try {
                    auto [key, list] = d.next_list_consumer();
                    assert(key == RETRYABLE_REQUESTS_KEY);
                    retry_list = std::move(list);
                } catch (const std::exception& e) {
                    result.bt.error = "Failed to read retryable request list: {}"_format(e.what());
                }

                while (result.bt.error.empty() && !retry_list.is_finished()) {
                    auto request_dict = retry_list.consume_dict_consumer();

                    RequestRetry request = {};
                    try {
                        request.cmd = request_dict.require<std::string>(COMMAND_KEY);
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to read retryable request command: {}"_format(e.what());
                        continue;
                    }

                    try {
                        request.req_payload = request_dict.require<std::string>(REQ_PAYLOAD_KEY);
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to read retryable request, request payload: {}"_format(
                                        e.what());
                        continue;
                    }

                    try {
                        uint64_t create_time_u64 = request_dict.require<uint64_t>(CREATE_TIME_KEY);
                        request.create_time = std::chrono::steady_clock::time_point(
                                std::chrono::milliseconds(create_time_u64));
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to read retryable request, create time: {}"_format(
                                        e.what());
                        continue;
                    }

                    oxenc::bt_list_consumer node_list("l");  // Dummy list
                    try {
                        auto [key, list] = request_dict.next_list_consumer();
                        assert(key == NODES_KEY);
                        node_list = std::move(list);
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to read retryable request, node list: {}"_format(e.what());
                        continue;
                    }

                    while (result.bt.error.empty() && !node_list.is_finished()) {
                        auto node_dict = node_list.consume_dict_consumer();
                        RequestRetryEntry node = {};
                        try {
                            std::string_view key_bytes =
                                    node_dict.require<std::string_view>(KEY_KEY);
                            node.key = crypto::legacy_pubkey::from_bytes(key_bytes);
                        } catch (const std::exception& e) {
                            result.bt.error =
                                    "Failed to parse retryable request node key: {}"_format(
                                            e.what());
                            continue;
                        }

                        try {
                            uint64_t deadline_u64 = node_dict.require<uint64_t>(DEADLINE_KEY);
                            node.deadline = std::chrono::steady_clock::time_point(
                                    std::chrono::milliseconds(deadline_u64));
                        } catch (const std::exception& e) {
                            result.bt.error =
                                    "Failed to parse retryable request node deadline: {}"_format(
                                            e.what());
                            continue;
                        }

                        try {
                            uint64_t next_retry_delay_u64 =
                                    node_dict.require<uint64_t>(NEXT_RETRY_DELAY_KEY);
                            node.next_retry_delay = std::chrono::milliseconds(next_retry_delay_u64);
                        } catch (const std::exception& e) {
                            result.bt.error =
                                    "Failed to parse retryable request next retry delay: {}"_format(
                                            e.what());
                            continue;
                        }

                        try {
                            uint32_t reason_u32 = node_dict.require<uint32_t>(REASON_KEY);
                            node.reason = static_cast<RetryReason>(reason_u32);
                        } catch (const std::exception& e) {
                            result.bt.error =
                                    "Failed to parse retryable request reason {}"_format(e.what());
                            continue;
                        }

                        request.nodes.emplace_back(std::move(node));
                    }
                    result.retryable_requests.emplace_back(std::move(request));
                }
            }
        }
        result.bt.success = result.bt.error.empty();
    }
    return result;
}

SerialiseSwarmsResult ServiceNode::serialize_swarms(
        Serialise serialise, std::string_view read_data) const {
    SerialiseSwarmsResult result = {};

    constexpr std::string_view VERSION_KEY = "@";
    constexpr std::string_view NETWORK_SWARMS_KEY = "network.swarms";
    constexpr std::string_view SWARM_CUR_SWARM_ID = "swarm.cur_swarm_id";
    constexpr std::string_view SWARM_MEMBERS_KEY = "swarm.members";

    uint32_t version = 0;
    if (serialise == Serialise::Write) {
        oxenc::bt_dict_producer d;
        d.append(VERSION_KEY, version);

        {
            oxenc::bt_list_producer network_swarm_list = d.append_list(NETWORK_SWARMS_KEY);
            for (auto it : network_.swarms_) {
                auto swarm = network_swarm_list.append_list();
                swarm.append<uint64_t>(it.first);  // swarm_id_t

                {  // Append list of pubkeys for this swarm
                    for (const crypto::legacy_pubkey& pk : it.second)
                        swarm.append<std::string_view>(pk.view());
                }
            }
        }

        d.append(SWARM_CUR_SWARM_ID, swarm_.cur_swarm_id_);

        {  // Append list of _our_ swarm members
            oxenc::bt_list_producer swarm_member_list = d.append_list(SWARM_MEMBERS_KEY);
            for (auto it : swarm_.members_)
                swarm_member_list.append(it.first);  // pk
        }

        result.bt.success = true;
        result.bt.write_payload = d.view();
    } else {
        if (read_data.size()) {
            oxenc::bt_dict_consumer d{read_data};
            try {
                version = d.require<uint8_t>(VERSION_KEY);
            } catch (const std::exception& e) {
                result.bt.error = "Failed to parse version: {}"_format(e.what());
            }

            if (result.bt.error.empty()) {
                // Initially a dummy list that we will std::move the real list into
                oxenc::bt_list_consumer swarm_list("l");
                try {
                    auto [key, list] = d.next_list_consumer();
                    assert(key == NETWORK_SWARMS_KEY);
                    swarm_list = std::move(list);
                } catch (const std::exception& e) {
                    result.bt.error = "Failed to parse network swarms: {}"_format(e.what());
                }

                while (result.bt.error.empty() && !swarm_list.is_finished()) {
                    auto swarm = swarm_list.consume_list_consumer();
                    uint64_t swarm_id = 0;
                    try {
                        swarm_id = swarm.consume<uint64_t>();
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to parse swarm id from swarm list: {}"_format(e.what());
                        continue;
                    }

                    std::set<crypto::legacy_pubkey>& keys = result.network_swarms[swarm_id];
                    while (result.bt.error.empty() && !swarm.is_finished()) {
                        try {
                            auto bytes = swarm.consume<std::string_view>();
                            keys.insert(keys.end(), crypto::legacy_pubkey::from_bytes(bytes));
                        } catch (const std::exception& e) {
                            result.bt.error =
                                    "Failed to parse swarm pubkey from swarm: {}"_format(e.what());
                        }
                    }
                }
            }

            if (result.bt.error.empty()) {
                try {
                    result.swarm_cur_swarm_id = d.require<uint64_t>(SWARM_CUR_SWARM_ID);
                } catch (const std::exception& e) {
                    result.bt.error =
                            "Failed to parse swarm's current swarm ID: {}"_format(e.what());
                }
            }

            if (result.bt.error.empty()) {
                oxenc::bt_list_consumer swarm_members("l");
                try {
                    auto [key, list] = d.next_list_consumer();
                    assert(key == SWARM_MEMBERS_KEY);
                    swarm_members = std::move(list);
                } catch (const std::exception& e) {
                    result.bt.error = "Failed to parse swarm members: {}"_format(e.what());
                }

                while (result.bt.error.empty() && !swarm_members.is_finished()) {
                    try {
                        auto bytes = swarm_members.consume<std::string_view>();
                        result.swarm_members[crypto::legacy_pubkey::from_bytes(bytes)] = {};
                    } catch (const std::exception& e) {
                        result.bt.error =
                                "Failed to parse swarm member from list: {}"_format(e.what());
                    }
                }
            }
        }
        result.bt.success = result.bt.error.empty();
    }

    return result;
}

ServiceNode::ServiceNode(
        const crypto::legacy_keypair& keys,
        const contact& contact,
        server::OMQ& omq_server,
        const std::filesystem::path& db_location,
        bool force_start,
        bool skip_bootstrap) :
        force_start_{force_start},
        skip_bootstrap_{skip_bootstrap},
        our_keys_{keys},
        our_contact_{contact},
        network_{*omq_server},
        omq_server_{omq_server},
        all_stats_{*omq_server},
        db{std::make_unique<Database>(db_location)} {
    mq_servers_.push_back(&omq_server);

    std::string swarms_blob = db->runtime_state_blob(BlobType::Swarms, Serialise::Read, "");
    SerialiseSwarmsResult swarm_result = serialize_swarms(Serialise::Read, swarms_blob);
    if (swarm_result.bt.success) {
        last_swarms_serialize_hash = fnv1a64_hasher(swarms_blob, FNV1A64_SEED);
        swarm_.members_ = std::move(swarm_result.swarm_members);
        network_.swarms_ = std::move(swarm_result.network_swarms);
        swarm_.cur_swarm_id_ = swarm_result.swarm_cur_swarm_id;
    } else {
        log::error(logcat, "Deserialising of swarms failed: {}", swarm_result.bt.error);
        swarms_blob.clear();
    }

    std::string retryable_blob =
            db->runtime_state_blob(BlobType::RetryableRequests, Serialise::Read, "");
    SerialiseRetryableRequestsResult retryable_result =
            serialize_retryable_requests(Serialise::Read, retryable_blob, {});
    if (retryable_result.bt.success) {
        last_retryable_serialize_hash = fnv1a64_hasher(retryable_blob, FNV1A64_SEED);
        retryable_requests = std::move(retryable_result.retryable_requests);
    } else {
        log::error(
                logcat,
                "Deserialising of retryable requests failed: {}",
                retryable_result.bt.error);
        retryable_blob.clear();
    }

    log::info(
            logcat,
            "Loaded {} ({}) swarms (#{:x}; in swarm {:x} w/ {} members) and {} ({}) retryable "
            "requests from disk. Requesting initial swarm state",
            network_.swarms_.size(),
            util::get_human_readable_bytes(swarms_blob.size()),
            last_swarms_serialize_hash,
            swarm_.cur_swarm_id_,
            swarm_.members_.size(),
            retryable_requests.size(),
            util::get_human_readable_bytes(retryable_blob.size()));

    // Check if the DB was empty and remember if so for later when talking to swarm members on
    // handshake that we need to request a DB dump from them to populate our DB. In the edge case
    // where there _are_ 0 messages, this will request a DB dump of 0 messages and essentially
    // no-op.
    if (db->get_message_count(Database::GetMessageCount::Owned) == 0) {
        // The 'cur_swarm_id' might be INVALID_SWARM_ID. This will be the case if the DB was deletd
        // (and so the blobs storing our swarms were also deleted). The swarm is then
        // bootstrapped to a proper swarm when we process the first handshake from a swarm member.
        swarm_.db_was_initially_empty_with_swarm_id = swarm_.cur_swarm_id_;
    }

    omq_server->add_timer(
            [this] {
                std::lock_guard l{sn_mutex_};
                db->clean_expired();
            },
            Database::CLEANUP_PERIOD);

    omq_server->add_timer([this] { check_new_members(); }, NEW_SWARM_MEMBER_INTERVAL);

    // We really want to make sure nodes don't get stuck in "syncing" mode,
    // so if we are still "syncing" after a long time, activate SN regardless
    auto delay_timer = std::make_shared<oxenmq::TimerID>();
    auto& dtimer = *delay_timer;  // Get reference before we move away the shared_ptr
    omq_server_->add_timer(
            dtimer,
            [this, timer = std::move(delay_timer)] {
                omq_server_->cancel_timer(*timer);
                std::lock_guard lock{sn_mutex_};
                if (!syncing_)
                    return;
                log::warning(logcat, "Block syncing is taking too long, activating SS regardless");
                syncing_ = false;
            },
            1h);

    // Setup the retryable requests thread
    retryable_requests_thread =
            std::thread(&ServiceNode::retryable_requests_thread_entry_point, this);
}

void ServiceNode::on_oxend_connected() {
    // This should be the first time we ever trigger a block update from Oxen, i.e. the initial
    // call to `update_swarms` should not early out which would cause a deadlock on the promise.
    assert(!updating_swarms_.load());
    auto started = std::chrono::steady_clock::now();

    bool success;
    do {
        std::promise<bool> update_swarms_promise;
        std::future<bool> update_swarms_result = update_swarms_promise.get_future();
        update_swarms(&update_swarms_promise);

        while (update_swarms_result.wait_for(5s) != std::future_status::ready)
            log::warning(logcat, "Still waiting for initial block update from oxend...");

        success = update_swarms_result.get();
    } while (!success);

    log::info(
            logcat,
            "Got initial block update from oxend in {} (height {}/{} HF {}.{})",
            util::short_duration(std::chrono::steady_clock::now() - started),
            block_height_,
            block_hash_,
            hardfork_.first,
            hardfork_.second);

    oxend_ping();
    omq_server_->add_timer([this] { oxend_ping(); }, OXEND_PING_INTERVAL);
    omq_server_->add_timer([this] { ping_peers(); }, reachability_testing::TESTING_TIMER_INTERVAL);
}

template <typename T>
static T get_or(const json& j, std::string_view key, std::common_type_t<T> default_val) {
    if (auto it = j.find(key); it != j.end())
        return it->get<T>();
    return default_val;
}

static std::optional<block_update> parse_swarm_update(
        std::string_view response_body, const crypto::legacy_pubkey& our_pk) {
    if (response_body.empty()) {
        log::critical(logcat, "Bad oxend rpc response: no response body");
        throw std::runtime_error("Failed to parse swarm update");
    }

    std::optional<block_update> maybe_bu;

    log::trace(logcat, "swarm response: <{}>", response_body);

    try {
        json result = json::parse(response_body, nullptr, true);
        if (result.value<bool>("unchanged", false))
            return maybe_bu;  // nullopt

        auto& bu = maybe_bu.emplace();

        bu.height = result.at("height").get<uint64_t>();
        bu.block_hash = result.at("block_hash").get<std::string>();
        bu.hardfork = result.at("hardfork").get<int>();
        bu.snode_revision = result.value<int>("snode_revision", 0);

        const json service_node_states = result.at("service_node_states");

        int missing_contacts = 0, total = 0;

        for (const auto& sn_json : service_node_states) {
            total++;
            const auto& pk_hex = sn_json.at("service_node_pubkey").get_ref<const std::string&>();

            const auto pk_x25519_hex = sn_json.value<std::string_view>("pubkey_x25519", ""sv);
            const auto pk_ed25519_hex = sn_json.value<std::string_view>("pubkey_ed25519", ""sv);

            auto pk = crypto::legacy_pubkey::from_hex(pk_hex);
            auto& c = bu.contacts[pk];
            c = contact{
                    ipv4{sn_json.value<std::string>("public_ip", "0.0.0.0")},
                    sn_json.value<uint16_t>("storage_port", 0),
                    sn_json.value<uint16_t>("storage_lmq_port", 0),
                    sn_json.value<std::array<uint16_t, 3>>("storage_server_version", {0, 0, 0}),
                    pk_ed25519_hex.empty() ? crypto::ed25519_pubkey{}
                                           : crypto::ed25519_pubkey::from_hex(pk_ed25519_hex),
                    pk_x25519_hex.empty() ? crypto::x25519_pubkey{}
                                          : crypto::x25519_pubkey::from_hex(pk_x25519_hex)};

            if (!c) {
                // oxend hasn't yet received an uptime proof from this node
                missing_contacts++;
                log::debug(logcat, "contact info is missing from service node info {}", pk_hex);
            }

            const swarm_id_t swarm_id = sn_json.at("swarm_id").get<swarm_id_t>();

            if (swarm_id != INVALID_SWARM_ID)
                bu.swarms[swarm_id].insert(pk);
            else if (pk == our_pk)
                bu.decommed = true;
        }

        if (missing_contacts >
            MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den) {
            log::warning(
                    logcat,
                    "Missing contact info for {}/{} service nodes; "
                    "oxend may be out of sync with the network",
                    missing_contacts,
                    total);
        }
    } catch (const std::exception& e) {
        log::critical(logcat, "Bad oxend rpc response: invalid json ({})", e.what());
        throw std::runtime_error("Failed to parse swarm update");
    }

    return maybe_bu;
}

void ServiceNode::add_retryable_request(RequestRetry&& item) {
    std::unique_lock lock{retryable_requests_mutex};
    retryable_requests.emplace_back(item);
    retryable_requests_cv.notify_all();  // Wake up retry thread
}

void ServiceNode::register_mq_server(server::MQBase* server) {
    mq_servers_.push_back(server);
}

void ServiceNode::bootstrap_fallback() {
    std::lock_guard guard(sn_mutex_);

    log::trace(logcat, "Bootstrapping peer data");

    // TODO: once all bootstraps are on 11.x releases, we can change the fields value to be an array
    // of field names rather than this dict of {"field": true, "field2": true, ...} pairs.
    std::string params = json{
            {"fields",
             {
                     {"service_node_pubkey", true},
                     {"swarm_id", true},
                     {"storage_port", true},
                     {"public_ip", true},
                     {"height", true},
                     {"block_hash", true},
                     {"hardfork", true},
                     {"snode_revision", true},
                     {"pubkey_x25519", true},
                     {"pubkey_ed25519", true},
                     {"storage_lmq_port", true},
                     {"storage_server_version", true},
             }}}.dump();

    std::vector<oxenmq::address> seed_nodes;
    if (oxenss::is_mainnet) {
        seed_nodes.emplace_back(
                "curve://storage.seed1.loki.network:22027/"
                "63089194d7ed97c9bb9c1112501b09be1b4b8ff026ceeb339532ce240da03178");
        seed_nodes.emplace_back(
                "curve://public-eu.optf.ngo:22027/"
                "3c157ed3c675f56280dc5d8b2f00b327b5865c127bf2c6c42becc3ca73d9132b");
        seed_nodes.emplace_back(
                "curve://imaginary.stream:22027/"
                "c0cab39382531e5b6c6325c0f980e9ffb79b20a4c82bb96571f1ffdc3ee76d58");
    } else {
        seed_nodes.emplace_back(
                "curve://storage.seed2.loki.network:38161/"
                "80adaead94db3b0402a6057869bdbe63204a28e93589fd95a035480ed6c03b45");
    }

    auto req_counter = std::make_shared<std::atomic<int>>(0);

    for (const auto& addr : seed_nodes) {
        auto connid = omq_server_->connect_remote(
                addr,
                [addr](oxenmq::ConnectionID) {
                    log::debug(logcat, "Connected to bootstrap node {}", addr.full_address());
                },
                [addr](oxenmq::ConnectionID, auto reason) {
                    log::debug(
                            logcat,
                            "Failed to connect to bootstrap node {}: {}",
                            addr.full_address(),
                            reason);
                },
                oxenmq::connect_option::ephemeral_routing_id{true},
                oxenmq::connect_option::timeout{BOOTSTRAP_TIMEOUT});
        omq_server_->request(
                connid,
                "rpc.get_service_nodes",
                [this, connid, addr, req_counter, node_count = (int)seed_nodes.size()](
                        bool success, std::vector<std::string> data) {
                    if (!success)
                        log::error(
                                logcat,
                                "Failed to contact bootstrap node {}: request timed out",
                                addr.full_address());
                    else if (data.empty())
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "no "
                                "data",
                                addr.full_address());
                    else if (data[0] != "200")
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "failure status {}",
                                addr.full_address(),
                                data[0]);
                    else {
                        log::info(
                                logcat,
                                "Parsing response from bootstrap node {}",
                                addr.full_address());
                        try {
                            std::lock_guard lock{sn_mutex_};
                            if (auto update = parse_swarm_update(data[1], our_keys_.pub))
                                on_bootstrap_update(std::move(*update));
                            log::info(logcat, "Bootstrapped from {}", addr.full_address());
                        } catch (const std::exception& e) {
                            log::error(
                                    logcat,
                                    "Exception caught while bootstrapping from {}: {}",
                                    addr.full_address(),
                                    e.what());
                        }
                    }

                    omq_server_->disconnect(connid);

                    if (++(*req_counter) == node_count) {
                        log::info(logcat, "Bootstrapping done");
                        if (target_height_ > 0)
                            update_swarms();
                        else {
                            // If target height is still 0 after having contacted
                            // (successfully or not) all seed nodes, just assume we have
                            // finished syncing. (Otherwise we will never get a chance
                            // to update syncing status.)
                            log::warning(
                                    logcat,
                                    "Could not contact any bootstrap nodes to get target "
                                    "height. Assuming our local height is correct.");
                            syncing_ = false;
                        }
                    }
                },
                params,
                oxenmq::send_option::request_timeout{BOOTSTRAP_TIMEOUT});
    }
}

void ServiceNode::shutdown() {
    shutting_down_ = true;
    retryable_requests_cv.notify_all();
    retryable_requests_thread.join();
}

bool ServiceNode::snode_ready(std::string* reason) {
    if (shutting_down()) {
        if (reason)
            *reason = "shutting down";
        return false;
    }

    std::lock_guard guard(sn_mutex_);

    std::vector<std::string> problems;

    if (!hf_at_least(STORAGE_SERVER_HARDFORK))
        problems.push_back(fmt::format(
                "not yet on hardfork {}.{}",
                STORAGE_SERVER_HARDFORK.first,
                STORAGE_SERVER_HARDFORK.second));
    if (syncing_)
        problems.push_back("not done syncing");

    if (reason && !problems.empty())
        *reason = "{}"_format(fmt::join(problems, "; "));

    return problems.empty() || force_start_;
}

std::optional<SwarmMemberState> ServiceNode::is_swarm_peer(const crypto::x25519_pubkey& xpk) {
    return swarm_.is_member(xpk);
}

void ServiceNode::send_onion_to_sn(
        const contact& ct,
        std::string_view payload,
        rpc::OnionRequestMetadata&& data,
        std::function<void(bool success, std::vector<std::string> data)> cb) const {
    // Since HF18 we bencode everything (which is a bit more compact than sending the eph_key in
    // hex, plus flexible enough to allow other metadata such as the hop number and the
    // encryption type).
    data.hop_no++;
    omq_server_->request(
            ct.pubkey_x25519.view(),
            "sn.onion_request",
            std::move(cb),
            oxenmq::send_option::request_timeout{30s},
            omq_server_.encode_onion_data(payload, data));
}

void ServiceNode::record_proxy_request() {
    all_stats_.bump_proxy_requests();
}

void ServiceNode::record_onion_request() {
    all_stats_.bump_onion_requests();
}

void ServiceNode::record_retrieve_request() {
    all_stats_.bump_retrieve_requests();
}

struct LookupRetryIndexes {
    std::optional<size_t> retryable_index;
    std::optional<size_t> node_index;
};

static LookupRetryIndexes lookup_retry_indexes(
        std::span<RequestRetry> retryable_requests,
        uint64_t request_hash,
        const crypto::legacy_pubkey& key) {
    LookupRetryIndexes result = {};

    // Find the retry request
    for (size_t index = 0; index < retryable_requests.size(); index++) {
        if (retryable_requests[index].hash == request_hash) {
            result.retryable_index = index;
            break;
        }
    }

    // Find the matching node inside the retry request
    if (result.retryable_index) {
        const RequestRetry& request = retryable_requests[*result.retryable_index];
        for (size_t index = 0; index < request.nodes.size(); index++) {
            if (request.nodes[index].key == key) {
                result.node_index = index;
                break;
            }
        }
    }

    return result;
}

void ServiceNode::check_new_members() {
    for (const auto& pk : swarm_.extract_contact_pending_members()) {
        auto c = network_.contacts.find(pk);
        if (!c || !*c) {
            // We don't have contact info, so don't do anything right now and this will get
            // triggered again later.
            log::debug(
                    logcat,
                    "Leaving {} as pending: node {}",
                    pk,
                    c ? "has missing contact info" : "is unknown");
            continue;
        }

        if (c->version < NEW_SWARM_MEMBER_HANDSHAKE_VERSION) {
            log::debug(
                    logcat,
                    "Skipping handshake with new swarm member {}: v{}+ required, remote is v{}",
                    pk,
                    fmt::join(NEW_SWARM_MEMBER_HANDSHAKE_VERSION, "."),
                    fmt::join(c->version, "."));

            std::lock_guard network_lock{network().mut_};
            if (SwarmMemberState* member = swarm_.is_member_locked(pk); member)
                member->status = SwarmMemberStatus::Ready;
            continue;
        }

        auto on_sn_data_ready_response = [this, pk](bool success, std::vector<std::string> data) {
            if (data.empty()) {
                success = false;
                data.push_back("Empty reply"s);
            } else if (data[0] != "OK"sv) {
                success = false;
            }

            if (success) {
                log::debug(
                        logcat,
                        "Successful contact made with swarm member {}, marking as ready",
                        pk);
            } else {
                log::info(
                        logcat,
                        "Failed to connect to remote SS {} to initiate new "
                        "data transfer ({}); will retry soon",
                        pk,
                        fmt::join(data, ", "));
            }

            // The 'pk' member might not be in the swarm anymore if the request elapsed over a
            // period of time where the swarm composition changed.
            std::lock_guard network_lock{network().mut_};
            if (SwarmMemberState* member = swarm_.is_member_locked(pk); member) {
                // Update the requested DB dump state machine if necessary.
                SwarmRequestedDBDump& status = member->our_ss_requested_db_dump;
                if (status == SwarmRequestedDBDump::RequestUnderway) {
                    status = success ? SwarmRequestedDBDump::Done
                                     : SwarmRequestedDBDump::NeedsToRequest;
                }

                if (success)
                    member->status = SwarmMemberStatus::Ready;
            }
        };

        if (c->version >= SN_DATA_READY_WITH_REQUEST_VERSION) {
            // Build 'data ready' request
            snode::DataReadyRequest request = {};
            {
                std::lock_guard network_lock{network().mut_};
                if (SwarmMemberState* member = swarm_.is_member_locked(pk); member) {
                    SwarmRequestedDBDump& status = member->our_ss_requested_db_dump;
                    if (status == SwarmRequestedDBDump::NeedsToRequest) {
                        status = SwarmRequestedDBDump::RequestUnderway;
                        request.needs_db_dump = true;
                    }
                }
            }

            // Serialise our response and send it off
            snode::SerialiseDataReadyRequestResult serialised =
                    snode::serialise_data_ready_request(Serialise::Write, "", request);
            assert(serialised.bt.success);

            log::debug(
                    logcat,
                    "Initiating contact with new swarm member {}{}",
                    pk,
                    request.needs_db_dump ? " (requesting DB dump)" : "");
            omq_server_->request(
                    c->pubkey_x25519.view(),
                    "sn.data_ready",
                    on_sn_data_ready_response,
                    std::move(serialised.bt.write_payload));
        } else {
            log::debug(logcat, "Initiating contact with new swarm member {}", pk);
            omq_server_->request(
                    c->pubkey_x25519.view(), "sn.data_ready", on_sn_data_ready_response);
        }
    }

    if (auto send_now = swarm_.extract_contacts_needing_db_dump(); !send_now.empty()) {
        auto msgs = db->retrieve_all();
        log::debug(
                logcat,
                "Initiating swarm message dump ({} message) to swarm member(s): {}",
                msgs.size(),
                fmt::join(send_now, ", "));
        relay_messages(std::move(msgs), send_now);
    }
}

static void write_metadata(
        oxenc::bt_dict_producer& d, std::string_view pubkey, const message& msg) {
    d.append("@", pubkey);
    d.append("h", msg.hash);
    d.append("n", to_int(msg.msg_namespace));
    d.append("t", to_epoch_ms(msg.timestamp));
    d.append("z", to_epoch_ms(msg.expiry));
}

void ServiceNode::send_notifies(message msg) {
    auto pubkey = msg.pubkey.prefixed_raw();
    std::vector<server::connection_id> relay_to, relay_to_with_data;

    for (auto* s : mq_servers_)
        s->get_notifiers(msg, relay_to, relay_to_with_data);

    if (relay_to.empty() && relay_to_with_data.empty())
        return;

    // We output a dict with keys (in order):
    // - @ pubkey
    // - h msg hash
    // - n msg namespace
    // - t msg timestamp
    // - z msg expiry
    // - ~ msg data (optional)
    constexpr size_t metadata_size = 2       // d...e
                                   + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                   + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                   + 3 + 8   // 1:n and i-32768e
                                   + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                   + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                   + 10;     // safety margin

    oxenc::bt_dict_producer d;
    d.reserve(
            relay_to_with_data.empty() ? metadata_size
                                       : metadata_size  // all the metadata above
                                                 + 3    // 1:~
                                                 + 8    // 76800: plus a couple bytes to grow
                                                 + msg.data.size());

    write_metadata(d, pubkey, msg);

    if (!relay_to.empty())
        for (auto* s : mq_servers_)
            s->notify(relay_to, d.view());

    if (!relay_to_with_data.empty()) {
        d.append("~", msg.data);
        for (auto* s : mq_servers_)
            s->notify(relay_to_with_data, d.view());
    }
}

bool ServiceNode::process_store(
        message msg, bool* new_msg, std::chrono::system_clock::time_point* expiry) {
    std::lock_guard guard{sn_mutex_};

    /// only accept a message if we are in a swarm
    if (!swarm_.is_valid()) {
        // This should never be printed now that we have "snode_ready"
        log::error(logcat, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database (if not already present)
    const auto result = db->store(msg, expiry);
    if (new_msg)
        *new_msg = result == StoreResult::New;

    if (result == StoreResult::New)
        send_notifies(std::move(msg));

    return result != StoreResult::Full;
}

void ServiceNode::save_bulk(const std::vector<message>& msgs) {
    try {
        db->bulk_store(msgs);
    } catch (const std::exception& e) {
        log::error(logcat, "failed to save batch to the database: {}", e.what());
        return;
    }

    log::trace(logcat, "saved messages count: {}", msgs.size());
}

static void store_swarms_blob_if_changed(
        uint64_t block_height,
        const SerialiseSwarmsResult& serialise_result,
        Database& db,
        uint64_t& last_hash) {
    if (serialise_result.bt.success) {
        uint64_t hash = fnv1a64_hasher(serialise_result.bt.write_payload, FNV1A64_SEED);
        if (last_hash != hash) {
            log::debug(
                    logcat,
                    "Swarm state dirtied at blk {}; #{:x} => #{:x}, saving {} to DB",
                    block_height,
                    last_hash,
                    hash,
                    util::get_human_readable_bytes(serialise_result.bt.write_payload.size()));
            last_hash = hash;
            db.runtime_state_blob(
                    BlobType::Swarms, Serialise::Write, serialise_result.bt.write_payload);
        }
    } else {
        if (static bool once = true; once) {
            once = false;
            log::error(
                    logcat,
                    "Failed to serialize swarms to blob: {}",
                    serialise_result.bt.write_payload);
        }
    }
}

void ServiceNode::on_bootstrap_update(block_update&& bu) {
    swarm_.update_swarms(bu.height, std::move(bu.swarms), bu.contacts);
    target_height_ = std::max(target_height_, bu.height);

    snode::SerialiseSwarmsResult write = serialize_swarms(Serialise::Write, "");
    store_swarms_blob_if_changed(block_height_, write, *db, last_swarms_serialize_hash);
}

void ServiceNode::on_snodes_update(block_update&& bu) {
    hf_revision net_ver{bu.hardfork, bu.snode_revision};
    if (hardfork_ != net_ver) {
        log::info(logcat, "New hardfork: {}.{}", net_ver.first, net_ver.second);
        hardfork_ = net_ver;
    }

    if (syncing_ && target_height_ != 0) {
        syncing_ = bu.height < target_height_;
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        log::debug(logcat, "Still syncing: {}/{}", bu.height, target_height_);
        // Note that because we are still syncing, we won't update our swarm id
        return;
    }

    if (bu.block_hash != block_hash_) {
        log::debug(logcat, "new block, height: {}, hash: {}", bu.height, bu.block_hash);

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;
    } else {
        log::trace(logcat, "already seen this block");
        return;
    }

    bool ready;
    if (std::string reason; !(ready = snode_ready(&reason)))
        log::warning(logcat, "Storage server is still not ready: {}", reason);
    else if (!active_) {
        // NOTE: because we never reset `active_` after we get decommissioned, this code won't run
        // when the node comes back again
        log::info(logcat, "Storage server is now active!");
        active_ = true;
    }

    auto events = swarm_.update_swarms(bu.height, std::move(bu.swarms), bu.contacts);

    // Serialise state to blob and store into DB if dirtied
    snode::SerialiseSwarmsResult write = serialize_swarms(Serialise::Write, "");
    store_swarms_blob_if_changed(block_height_, write, *db, last_swarms_serialize_hash);

    if (const SnodeStatus status = events.our_swarm_id != INVALID_SWARM_ID ? SnodeStatus::ACTIVE
                                 : bu.decommed ? SnodeStatus::DECOMMISSIONED
                                               : SnodeStatus::UNSTAKED;
        status != status_) {

        log::info(logcat, "Node status updated: {}", status);
        status_ = status;
    }

    if (!ready)
        return;

    if (!events.new_swarms.empty())
        bootstrap_swarms(events.new_swarms);

    if (events.dissolved)
        /// Go through all our PK and push them accordingly
        bootstrap_swarms();
}

void ServiceNode::update_swarms(std::promise<bool>* on_finish) {
    if (updating_swarms_.exchange(true)) {
        log::debug(logcat, "Swarm update already in progress, not sending another update request");
        return;
    }

    std::lock_guard lock{sn_mutex_};

    log::debug(logcat, "Swarm update triggered");

    json params{
            {"fields",
             {
                     "block_hash",
                     "hardfork",
                     "height",
                     "pubkey_ed25519",
                     "pubkey_x25519",
                     "public_ip",
                     "service_node_pubkey",
                     "snode_revision",
                     "storage_lmq_port",
                     "storage_port",
                     "storage_server_version",
                     "swarm_id",
             }},
            {"active_only", false}};
    if (got_first_response_ && !block_hash_.empty())
        params["poll_block_hash"] = block_hash_;

    omq_server_.oxend_request(
            "rpc.get_service_nodes",
            [this, on_finish](bool success, std::vector<std::string> data) {
                updating_swarms_ = false;
                if (!success || data.size() < 2 || data[0] != "200") {
                    log::critical(
                            logcat,
                            "Failed to retrieve snode list from oxend: {}",
                            fmt::join(data, " "));
                    if (on_finish)
                        on_finish->set_value(false);
                    return;
                }

                try {
                    process_snodes_update(data[1]);
                } catch (const std::exception& e) {
                    log::error(logcat, "Exception caught on swarm update: {}", e.what());
                    if (on_finish)
                        on_finish->set_value(false);
                    return;
                }

                if (on_finish)
                    on_finish->set_value(true);
            },
            params.dump());
}

void ServiceNode::set_member_needs_db_dump(const crypto::legacy_pubkey& pk) {
    std::lock_guard lock{network().mut_};  // Use the same lock as Swarm member functions
    if (SwarmMemberState* state = swarm_.is_member_locked(pk); state)
        state->their_ss_needs_db_dump = true;
}

void ServiceNode::process_snodes_update(std::string_view data) {
    auto maybe_bu = parse_swarm_update(data, our_keys_.pub);

    std::lock_guard lock{sn_mutex_};

    if (maybe_bu) {
        log::debug(logcat, "Blockchain updated, rebuilding swarm list");
        on_snodes_update(std::move(*maybe_bu));
    }

    if (got_first_response_.exchange(true))
        return;

    log::info(logcat, "Got initial swarm information from local Oxend");
    // This is our very first response and so we *may* want to try falling back to the bootstrap
    // node *if* our response looks sparse: this will typically happen for a fresh service node
    // because IP/port distribution through the network can take up to an hour.  We don't really
    // want to hit the bootstrap nodes when we don't have to, though, so only do it if our responses
    // is missing more than 3% of proof data (IPs/ports/ed25519/x25519 pubkeys) or we got back fewer
    // than 100 SNs (10 on testnet).
    //
    // (In the future it would be nice to eliminate this by putting all the required data on chain,
    // and get rid of needing to consult bootstrap nodes: but currently we still need this to deal
    // with the lag).

    auto [total, contactable] = network_.contacts.counts();
    auto missing = total - contactable;

    if (skip_bootstrap_ ||
        (total >= (oxenss::is_mainnet ? 100 : 10) &&
         missing <= MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den)) {
        log::info(
                logcat,
                "Initialized from oxend with {}/{} contactable service nodes",
                contactable,
                total);
        syncing_ = false;
    } else {
        log::info(
                logcat,
                "Detected some missing SN data ({}/{} contactable); "
                "falling back to bootstrap nodes for help",
                contactable,
                total);
        bootstrap_fallback();
    }
}

void ServiceNode::update_last_ping(ReachType type) {
    reach_records_.incoming_ping(type);
}

void ServiceNode::ping_peers() {
    std::lock_guard lock{sn_mutex_};

    // TODO: Don't do anything until we are fully funded

    if (status_ == SnodeStatus::UNSTAKED || status_ == SnodeStatus::UNKNOWN) {
        log::trace(logcat, "Skipping peer testing (unstaked)");
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // Check if we've been tested (reached) recently ourselves
    reach_records_.check_incoming_tests(now);

    if (status_ == SnodeStatus::DECOMMISSIONED) {
        log::trace(logcat, "Skipping peer testing (decommissioned)");
        return;
    }

    /// We always test nodes due to be tested plus one general, non-failing node.

    auto to_test = reach_records_.get_failing(now);
    for (int i = 0; i < reachability_testing::RANDOM_TESTS_PER_TICK; i++) {
        auto rando = reach_records_.next_random(swarm_, now);
        if (!rando)
            break;
        to_test.emplace_back(std::move(*rando), 0);
    }

    if (to_test.empty())
        log::trace(logcat, "no nodes to test this tick");
    else
        log::debug(logcat, "{} nodes to test", to_test.size());
    for (const auto& [sn, prev_fails] : to_test)
        test_reachability(sn, prev_fails);
}

void ServiceNode::test_reachability(const crypto::legacy_pubkey& sn, int previous_failures) {
    log::debug(
            logcat,
            "Testing {} SN {} for reachability",
            previous_failures > 0 ? "previously failing" : "random",
            sn);

    auto http = http_.lock();
    if (!http) {
        log::debug(logcat, "Skipping reachability test during shutdown");
        return;
    }

    auto c = network_.contacts.find(sn);
    if (!c || !*c) {
        // oxend won't accept uncontactable info in an uptime proof, which means if we get here the
        // node hasn't sent an uptime proof; we could treat it as a failure, but that seems
        // unnecessary since oxend will already fail the service node for not sending uptime proofs.
        log::debug(logcat, "Not testing {}: node is uncontactable", sn);
        reach_records_.remove_node_from_failing(sn);
        return;
    }

    auto test = std::make_shared<sn_test>(
            sn,
            1 + mq_servers_.size(),
            [this, previous_failures](const crypto::legacy_pubkey& sn, bool passed) {
                report_reachability(sn, passed, previous_failures);
            });

    for (auto* mq : mq_servers_)
        mq->reachability_test(test);

    auto url = fmt::format("https://{}:{}/ping_test/v1", c->ip, c->https_port);
    std::optional<std::string> host;
    host = "{}.snode"_format(oxenc::to_base32z(sn.view()));

    log::debug(logcat, "Sending HTTPS ping to {} @ {}", sn, url);
    http->post(
            [test](cpr::Response r) {
                const auto& pk = test->pubkey;
                bool success = false;
                if (r.error.code != cpr::ErrorCode::OK) {
                    log::debug(logcat, "FAILED HTTPS ping test of {}: {}", pk, r.error.message);
                } else if (r.status_code != 200) {
                    log::debug(
                            logcat,
                            "FAILED HTTPS ping test of {}: received non-200 status {} {}",
                            pk,
                            r.status_code,
                            r.status_line);
                } else {
                    if (auto it = r.header.find(http::SNODE_PUBKEY_HEADER); it == r.header.end())
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: {} response header missing",
                                pk,
                                http::SNODE_PUBKEY_HEADER);
                    else if (auto remote_pk = crypto::parse_legacy_pubkey(it->second);
                             remote_pk != pk)
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: reply has wrong pubkey {}",
                                pk,
                                remote_pk);
                    else
                        success = true;
                }
                if (success)
                    log::debug(logcat, "Successful HTTPS ping test of {}", pk);

                test->add_result(success);
            },
            std::move(url),
            ""s /*body*/,
            SN_PING_TIMEOUT,
            std::move(host),
            true /*disable https validation*/);
}

void ServiceNode::oxend_ping() {
    std::lock_guard guard(sn_mutex_);

    json oxend_params{
            {"version", STORAGE_SERVER_VERSION},
            {"pubkey_ed25519", our_contact_.pubkey_ed25519.hex()},
            {"https_port", our_contact_.https_port},
            {"omq_port", our_contact_.omq_quic_port}};

    omq_server_.oxend_request(
            "admin.storage_server_ping",
            [this](bool success, std::vector<std::string> data) {
                if (!success)
                    log::critical(
                            logcat, "Could not ping oxend: Request failed ({})", data.front());
                else if (data.size() < 2 || data[1].empty())
                    log::critical(logcat, "Could not ping oxend: Empty body on reply");
                else
                    try {
                        if (const auto status =
                                    json::parse(data[1]).at("status").get<std::string>();
                            status == "OK") {
                            auto good_pings = ++oxend_pings_;
                            if (good_pings == 1)  // First ping after startup or after ping failure
                                log::info(logcat, "Successfully pinged oxend");
                            else if (good_pings % (1h / OXEND_PING_INTERVAL) == 0)  // Once an hour
                                log::info(logcat, "{} successful oxend pings", good_pings);
                            else
                                log::debug(
                                        logcat,
                                        "Successfully pinged Oxend ({} consecutive times)",
                                        good_pings);
                        } else {
                            log::critical(logcat, "Could not ping oxend: {}", status);
                            oxend_pings_ = 0;
                        }
                    } catch (...) {
                        log::critical(logcat, "Could not ping oxend: bad json in response");
                    }
            },
            oxend_params.dump());

    // Also re-subscribe (or subscribe, in case oxend restarted) to block and snode address
    // subscriptions.  This makes oxend start firing notify.block/notify.snode_addr messages at as
    // whenever new blocks or contact-changing proofs arrive, but we have to renew the subscriptions
    // within 30min to keep them alive, so do it here (it doesn't hurt anything for it to be much
    // faster than 30min).
    omq_server_.oxend_request("sub.block", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to oxend block notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to oxend new block notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed oxend new block notification subscription");
    });

    omq_server_.oxend_request("sub.snode_addr", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to oxend address notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to oxend address change notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed oxend address change notification subscription");
    });
}

void ServiceNode::report_reachability(
        const crypto::legacy_pubkey& sn_pk, bool reachable, int previous_failures) {
    auto cb = [sn_pk, reachable](bool success, std::vector<std::string> data) {
        if (!success) {
            log::warning(
                    logcat,
                    "Could not report node status: {}",
                    data.empty() ? "unknown reason" : data[0]);
            return;
        }

        if (data.size() < 2 || data[1].empty()) {
            log::warning(logcat, "Empty body on Oxend report node status");
            return;
        }

        try {
            const auto status = json::parse(data[1]).at("status").get<std::string>();

            if (status == "OK") {
                log::debug(
                        logcat,
                        "Successfully reported {} node: {}",
                        reachable ? "reachable" : "UNREACHABLE",
                        sn_pk);
            } else {
                log::warning(logcat, "Could not report node: {}", status);
            }
        } catch (...) {
            log::error(logcat, "Could not report node status: bad json in response");
        }
    };

    json params{{"type", "storage"}, {"pubkey", sn_pk.hex()}, {"passed", reachable}};

    omq_server_.oxend_request("admin.report_peer_status", std::move(cb), params.dump());

    if (!reachable || previous_failures > 0) {
        std::lock_guard guard(sn_mutex_);
        if (!reachable)
            reach_records_.add_failing_node(sn_pk, previous_failures);
        else
            reach_records_.remove_node_from_failing(sn_pk);
    }
}

void ServiceNode::bootstrap_swarms(const std::set<swarm_id_t>& swarms) const {
    std::lock_guard guard(sn_mutex_);

    if (swarms.empty())
        log::info(logcat, "Bootstrapping all swarms");
    else if (logcat->level() <= log::Level::info)
        log::info(logcat, "Bootstrapping swarms: [{}]", fmt::join(swarms, ", "));

    std::unordered_map<user_pubkey, swarm_id_t> pk_swarm_cache;
    std::unordered_map<swarm_id_t, std::vector<message>> to_relay;

    std::vector<message> all_msgs = db->retrieve_all();
    log::debug(logcat, "We have {} messages", all_msgs.size());
    for (auto& entry : all_msgs) {
        if (!entry.pubkey) {
            log::error(logcat, "Invalid pubkey in a message while bootstrapping other nodes");
            continue;
        }

        auto [it, ins] = pk_swarm_cache.try_emplace(entry.pubkey);
        if (ins)
            it->second = network_.get_swarm_id_for(entry.pubkey).value_or(INVALID_SWARM_ID);
        auto swarm_id = it->second;

        if (swarms.empty() || swarms.count(swarm_id))
            to_relay[swarm_id].push_back(std::move(entry));
    }

    log::trace(logcat, "Bootstrapping {} swarms", to_relay.size());

    for (const auto& [swarm_id, items] : to_relay)
        if (auto swarm = network_.get_swarm(swarm_id))
            relay_messages(items, *swarm);
}

void ServiceNode::relay_messages(
        const std::vector<message>& messages, const std::set<crypto::legacy_pubkey>& snodes) const {
    std::vector<std::string> batches =
            serialize_messages(messages.begin(), messages.end(), SERIALIZATION_VERSION_BT);

    if (logcat->level() <= log::Level::debug) {
        log::debug(logcat, "Relaying messages:");
        for (auto msg : batches)
            log::trace(logcat, "    {}", msg);
        log::debug(logcat, "To Snodes:");
        for (auto sn : snodes)
            log::debug(logcat, "    {}", sn);

        log::debug(logcat, "Serialised batches: {}", batches.size());
    }

    for (const auto& sn : snodes) {
        auto ct = network_.contacts.find(sn);
        if (ct && *ct) {
            for (auto& batch : batches) {
                log::debug(
                        logcat, "Relaying data to: {} (x25519 pubkey {})", sn, ct->pubkey_x25519);

                omq_server_->request(
                        ct->pubkey_x25519.view(),
                        "sn.data",
                        [](bool success, auto&& /*data*/) {
                            if (!success)
                                log::error(logcat, "Failed to relay batch data: timeout");
                        },
                        batch);
            }
        } else {
            log::warning(
                    logcat,
                    "Unable to relay messages to {}: node is not currently contactable",
                    sn);
        }
    }
}

void to_json(nlohmann::json& j, const test_result& val) {
    j["timestamp"] = std::chrono::duration<double>(val.timestamp.time_since_epoch()).count();
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats& stats) {
    json peers;
    for (const auto& [pk, stats] : stats.peer_report()) {
        auto& p = peers[pk.hex()];

        p["requests_failed"] = stats.requests_failed;
        p["pushes_failed"] = stats.requests_failed;
    }

    auto [window, recent] = stats.get_recent_requests();
    return json{
            {"total_store_requests", stats.get_total_store_requests()},
            {"total_retrieve_requests", stats.get_total_retrieve_requests()},
            {"total_onion_requests", stats.get_total_onion_requests()},
            {"total_proxy_requests", stats.get_total_proxy_requests()},

            {"recent_timespan", std::chrono::duration<double>(window).count()},
            {"recent_store_requests", recent.client_store_requests},
            {"recent_retrieve_requests", recent.client_retrieve_requests},
            {"recent_onion_requests", recent.onion_requests},
            {"recent_proxy_requests", recent.proxy_requests},

            {"peers", std::move(peers)}};
}

std::string ServiceNode::get_stats_for_session_client() const {
    return json{{"version", STORAGE_SERVER_VERSION_STRING}}.dump();
}

std::string ServiceNode::get_stats() const {
    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    std::vector<int> counts = db->get_message_counts();
    int64_t total = std::accumulate(counts.begin(), counts.end(), int64_t{0});

    counts.erase(
            std::remove_if(counts.begin(), counts.end(), [](int c) { return c < 2; }),
            counts.end());

    // If less than 5 our iterators below could end up at the same position, so just require at
    // least 5 rather than worrying about that case:
    if (counts.size() >= 5) {
        // We're going to calculate a few numbers here from the list of stored account sizes:
        // - minimum
        // - 5th percentile
        // - 25th percentile
        // - median (i.e. 50th percentile)
        // - 75th percentile
        // - 95th percentile
        // - maximum
        // - total
        // - mean
        //
        // To get a percentile we partially sort the data via nth_element; we don't muck around with
        // averaging the middle two elements or anything like that (because that's of limited actual
        // real world use) and instead just use the upper value by rounding up.  These look a little
        // weird as `size-1+n` values but that's because we to divide the top index, not the size.
        auto pct_5th = std::next(counts.begin(), (counts.size() - 1 + 19) / 20 - 1);
        auto pct_25th = std::next(counts.begin(), (counts.size() - 1 + 3) / 4 - 1);
        auto pct_50th = std::next(counts.begin(), (counts.size() - 1) / 2 - 1);
        auto pct_75th = std::next(counts.begin(), (3 * counts.size() - 1 + 3) / 4 - 1);
        auto pct_95th = std::next(counts.begin(), (19 * counts.size() - 1 + 19) / 20);
        std::nth_element(counts.begin(), pct_5th, counts.end());
        std::nth_element(std::next(pct_5th), pct_25th, counts.end());
        std::nth_element(std::next(pct_25th), pct_50th, counts.end());
        std::nth_element(std::next(pct_50th), pct_75th, counts.end());
        std::nth_element(std::next(pct_75th), pct_95th, counts.end());

        val["account_msg_count_min"] = *std::min_element(counts.begin(), pct_5th);
        val["account_msg_count_max"] = *std::max_element(pct_95th, counts.end());
        val["account_msg_count_5th"] = *pct_5th;
        val["account_msg_count_25th"] = *pct_25th;
        val["account_msg_count_median"] = *pct_50th;
        val["account_msg_count_75th"] = *pct_75th;
        val["account_msg_count_95th"] = *pct_95th;
    }

    val["accounts"] = counts.size();
    val["total_stored"] = total;
    if (counts.size() > 0)
        val["account_msg_mean"] = total / (double)counts.size();

    auto& ns_stats = (val["namespace_messages"] = nlohmann::json::object());
    for (auto& [ns, count] : db->get_namespace_counts())
        ns_stats[fmt::format("{}", ns)] = count;

    val["dbused"] = db->get_used_bytes();
    val["dbtotal"] = db->get_total_bytes();
    val["dbmax"] = Database::SIZE_LIMIT;

    return val.dump();
}

std::string ServiceNode::get_status_line() const {
    // This produces a short, single-line status string, used when running as a
    // systemd Type=notify service to update the service Status line.  The
    // status message has to be fairly short: has to fit on one line, and if
    // it's too long systemd just truncates it when displaying it.

    std::lock_guard guard(sn_mutex_);

    std::string swarm_disp;
    if (auto our_swid = swarm_.our_swarm_id(); our_swid == INVALID_SWARM_ID)
        swarm_disp = "NONE";
    else {
        std::string swarm_hex = "{:016x}"_format(swarm_.our_swarm_id());
        std::string_view sw{swarm_hex};
        swarm_disp = "{}…{}(n={})"_format(sw.substr(0, 4), sw.substr(sw.size() - 3), swarm_.size());
    }
    auto [window, stats] = all_stats_.get_recent_requests();

    // v2.3.4; sw=abcd…789(n=7); 1234 msgs (47.3 MB) for 567 users; reqs(S/R/O/P):
    // 123/456/789/1011 (last 62.3min)
    return "v{}{}{}; {} msgs ({}) for {} accts; reqs(S/R/O/P): {}/{}/{}/{} (last {})"_format(
            STORAGE_SERVER_VERSION_STRING,
            oxenss::is_mainnet ? "" : " (TESTNET)",
            syncing_ ? "; SYNCING" : "",
            db->get_message_count(Database::GetMessageCount::All),
            util::get_human_readable_bytes(db->get_used_bytes()),
            db->get_owner_count(),
            stats.client_store_requests,
            stats.client_retrieve_requests,
            stats.onion_requests,
            stats.proxy_requests,
            util::short_duration(window));
}

void ServiceNode::process_push_batch(std::string_view blob, std::string_view sender) {
    if (blob.empty())
        return;

    std::vector<message> items;
    try {
        items = deserialize_messages(blob);
    } catch (const std::exception& e) {
        log::warning(
                logcat,
                "Failed to deserialize incoming message batch from {}: {}",
                sender,
                e.what());
    }

    log::trace(logcat, "Saving all: begin");

    log::debug(logcat, "Got {} messages from peers, size: {}", items.size(), blob.size());

    save_bulk(items);

    log::trace(logcat, "Saving all: end");
}

void ServiceNode::retryable_requests_thread_entry_point() {
    // The min and max amount of time this node will backoff between failed retry requests
    constexpr auto MIN_RETRY_DELAY = 1s;
    constexpr auto MAX_RETRY_DELAY = 60s;
    constexpr auto RETRY_BACKOFF_COEFF = 1.75f;

    while (!shutting_down_) {
        // At longest, we timeout on the blocking sleep every 5s, or, as soon as someone wakes up
        // the thread by notifying the condition var
        //  - when a new retryable request is added
        //  - we're shutting down
        //  - or we know there's an earlier deadline in the list of requests to be retried
        //  - a node's contact detail was updated
        //  - a retryable request failed and a new deadline was posted
        auto earliest_deadline = std::chrono::steady_clock::now() + 5s;

        std::unique_lock lock{retryable_requests_mutex};
        retryable_requests_cv.wait_until(lock, earliest_deadline);

        if (shutting_down_)
            continue;

        // Log the current retries
        auto now = std::chrono::steady_clock::now();
        if (log::Level level = log::Level::debug;
            log::get_level(logcat) <= level && retryable_requests.size()) {

            size_t due_requests = 0;
            size_t total_requests = 0;
            fmt::memory_buffer trace_buffer;
            for (size_t index = 0; index < retryable_requests.size(); index++) {
                const auto& item = retryable_requests[index];
                auto item_age =
                        std::chrono::duration_cast<std::chrono::seconds>(now - item.create_time);
                if (item_age >= rpc::TTL_MAXIMUM_PRIVATE)
                    continue;

                if (log::get_level(logcat) <= log::Level::trace) {
                    fmt::format_to(
                            std::back_inserter(trace_buffer),
                            "{}  [{}] '{}' command {} to {} node(s)",
                            index ? "\n" : "",
                            index,
                            item.cmd,
                            util::get_human_readable_bytes(item.req_payload.size()),
                            item.nodes.size());
                }

                for (size_t node_index = 0; node_index < item.nodes.size(); node_index++) {
                    const auto& node_item = item.nodes[node_index];
                    bool is_due = now >= node_item.deadline;
                    due_requests += is_due;

                    if (log::get_level(logcat) <= log::Level::trace) {
                        if (node_index == 0)
                            fmt::format_to(std::back_inserter(trace_buffer), "\n  NODES");

                        std::string_view reason = "";
                        switch (node_item.reason) {
                            case RetryReason::NON_CONTACTABLE: reason = "non-contactable"; break;
                            case RetryReason::FAILED_TO_SEND: reason = "failed to send"; break;
                        }

                        std::string deadline = "now";
                        if (!is_due) {
                            auto delta = node_item.deadline - now;
                            deadline = "in {}"_format(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(delta));
                        }

                        fmt::format_to(
                                std::back_inserter(trace_buffer),
                                "\n    {}: {} ({}) retrying {}",
                                index,
                                node_item.key,
                                reason,
                                deadline);
                    }
                }

                total_requests += item.nodes.size();
            }

            log::log(
                    logcat,
                    level,
                    "Attempting {}/{} retryable requests",
                    due_requests,
                    total_requests);

            if (log::get_level(logcat) <= log::Level::trace)
                log::trace(logcat, "Retryables:\n{}", fmt::to_string(trace_buffer));
        }

        for (auto it = retryable_requests.begin(); it != retryable_requests.end();) {
            // Create a hash of the inputs so that we can match dispatched requests easily with the
            // originating retry item.
            if (it->hash == 0) {
                it->hash = FNV1A64_SEED;
                it->hash = fnv1a64_hasher(it->cmd, it->hash);
                it->hash = fnv1a64_hasher(it->req_payload, it->hash);
            }

            auto it_age = std::chrono::duration_cast<std::chrono::seconds>(now - it->create_time);
            if (it_age >= rpc::TTL_MAXIMUM_PRIVATE) {
                log::debug(logcat, "Retry request ({}) expired after {}", it->cmd, it_age);
                it->nodes.clear();
            }

            for (auto node_it = it->nodes.begin(); node_it != it->nodes.end();) {
                auto on_request_done = [MIN_RETRY_DELAY,
                                        MAX_RETRY_DELAY,
                                        this,
                                        hash = it->hash,
                                        key = node_it->key](
                                               bool success, std::vector<std::string> parts) {
                    std::unique_lock lock{retryable_requests_mutex};

                    // Lookup the originating retry-request responsible for this OMQ response
                    LookupRetryIndexes lookup = lookup_retry_indexes(retryable_requests, hash, key);
                    if (!lookup.retryable_index)
                        return;

                    RequestRetry& request = retryable_requests[*lookup.retryable_index];
                    if (lookup.node_index) {
                        RequestRetryEntry& node = request.nodes[*lookup.node_index];
                        node.retry_underway = false;

                        // We cleanup the request in all situations except timeout (timeout
                        // indicating that the node was non-responsive, maybe offline). In an error
                        // state we don't know what state the recipient's storage server is in and
                        // we default to deleting it and ending the retry attempts.
                        rpc::SNStorageCCResult store_result =
                                rpc::interpret_sn_storage_cc_response_parts(success, parts);
                        bool cleanup = store_result.status != rpc::SNStorageCCResultStatus::Timeout;

                        if (cleanup) {
                            std::string_view outcome = "succeeded";
                            if (store_result.status != rpc::SNStorageCCResultStatus::Good)
                                outcome = "failed unrecoverably";

                            log::debug(
                                    logcat,
                                    "Retry to {} for {} ({}) {}, cleaning up",
                                    key,
                                    request.cmd,
                                    util::get_human_readable_bytes(request.req_payload.size()),
                                    outcome);

                            request.nodes.erase(request.nodes.begin() + *lookup.node_index);
                        } else {
                            // Extend the next retry deadline and re-attempt later
                            node.next_retry_delay = std::max(
                                    node.next_retry_delay,
                                    std::chrono::milliseconds(MIN_RETRY_DELAY));

                            size_t delay_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      node.next_retry_delay)
                                                      .count();
                            delay_ms *= RETRY_BACKOFF_COEFF;
                            node.next_retry_delay = std::min(
                                    std::chrono::milliseconds(delay_ms),
                                    std::chrono::milliseconds(MAX_RETRY_DELAY));
                            node.deadline =
                                    std::chrono::steady_clock::now() + node.next_retry_delay;

                            // Wake up retryable request thread, it will take into consideration the
                            // new deadline for the blocking sleep
                            retryable_requests_cv.notify_all();

                            log::debug(
                                    logcat,
                                    "Retry to {} for {} ({}) timed out, next attempt in ~{}",
                                    key,
                                    request.cmd,
                                    util::get_human_readable_bytes(request.req_payload.size()),
                                    node.next_retry_delay);
                        }
                    }

                    // Remove retryable request if there are no more nodes to retry to
                    if (request.nodes.empty())
                        retryable_requests.erase(
                                retryable_requests.begin() + *lookup.retryable_index);
                };

                std::optional<SwarmMemberState> is_member = swarm_.is_member(node_it->key);
                if (is_member && !node_it->retry_underway) {
                    // Retry request if ready
                    bool is_due = now >= node_it->deadline;
                    bool ready = is_member->status == SwarmMemberStatus::Ready;
                    crypto::x25519_pubkey pubkey_x25519 = {};

                    if (ready) {
                        auto ct = contacts().find(node_it->key);
                        if (ct && *ct)
                            pubkey_x25519 = ct->pubkey_x25519;
                    }

                    if (pubkey_x25519) {
                        if (is_due) {
                            node_it->retry_underway = true;
                            omq_server()->request(
                                    pubkey_x25519.view(),
                                    "sn.storage_cc",
                                    on_request_done,
                                    it->cmd,
                                    it->req_payload,
                                    oxenmq::send_option::request_timeout{5s});
                        } else {
                            earliest_deadline = std::min(earliest_deadline, node_it->deadline);
                        }
                    }

                    if (!ready) {
                        log::debug(
                                logcat,
                                "Retry to {} ({}) deferred, member hasn't signaled 'data ready' "
                                "(was {})",
                                node_it->key,
                                it->cmd,
                                static_cast<uint8_t>(is_member->status));
                    } else if (!pubkey_x25519) {
                        log::debug(
                                logcat,
                                "Retry to {} ({}) deferred, contact info missing",
                                node_it->key,
                                it->cmd);
                    }
                }

                if (is_member) {
                    node_it++;
                } else {
                    log::debug(
                            logcat,
                            "Retry to {} ({}) cancelled, not a member in swarm anymore",
                            node_it->key,
                            it->cmd);
                    node_it = it->nodes.erase(node_it);
                }
            }

            if (it->nodes.empty())
                it = retryable_requests.erase(it);
            else
                it++;
        }

        SerialiseRetryableRequestsResult write =
                serialize_retryable_requests(Serialise::Write, "", retryable_requests);
        if (write.bt.success) {
            uint64_t hash = fnv1a64_hasher(write.bt.write_payload, FNV1A64_SEED);
            if (last_retryable_serialize_hash != hash) {
                log::debug(
                        logcat,
                        "Retryable requests dirtied #{:x} => #{:x}, saving {} to DB",
                        last_retryable_serialize_hash,
                        hash,
                        util::get_human_readable_bytes(write.bt.write_payload.size()));
                last_retryable_serialize_hash = hash;
                db->runtime_state_blob(
                        BlobType::RetryableRequests, Serialise::Write, write.bt.write_payload);
            }
        } else {
            if (static bool once = true; once) {
                once = false;
                log::error(
                        logcat,
                        "Failed to serialize retryable requests to blob: {}",
                        write.bt.write_payload);
            }
        }
    }
}
}  // namespace oxenss::snode
