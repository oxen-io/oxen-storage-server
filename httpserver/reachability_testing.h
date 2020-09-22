#pragma once

#include "loki_common.h"
#include <chrono>
#include <unordered_map>

using namespace std::chrono_literals;

constexpr std::chrono::seconds PING_PEERS_INTERVAL = 10s;

namespace loki {

namespace detail {

/// TODO: make this class "private"?
class reach_record_t {

  public:
    // The time the node failed for the first time
    // (and hasn't come back online)
    time_point_t first_failure;
    time_point_t last_failure;
    // whether it's been reported to Lokid
    bool reported = false;

    // whether reachable over http
    bool http_ok = true;
    // whether reachable over zmq
    bool zmq_ok = true;

    reach_record_t();
};
} // namespace detail

enum class ReachType { HTTP, ZMQ };

enum class ReportType { GOOD, BAD };

class reachability_records_t {

    // TODO: sn_records are heavy (3 strings), so how about we only store the
    // pubkey?

    // Nodes that failed the reachability test
    // Note: I don't expect this list to be large, so
    // `std::vector` is probably faster than `std::set` here
    std::unordered_map<sn_pub_key_t, detail::reach_record_t> offline_nodes_;

  public:
    // The time we were last tested and reached by some other node over lmq
    time_point_t latest_incoming_lmq_;
    // The time we were last tested and reached by some other node over http
    time_point_t latest_incoming_http_;

    // These will be set to `false` if we stop receiving lmq/http pings
    bool lmq_ok = true;
    bool http_ok = true;

    // Check whether we received incoming pings recently
    void check_incoming_tests(time_point_t reset_time);

    // Records node as reachable/unreachable according to `val`
    void record_reachable(const sn_pub_key_t& sn, ReachType type, bool val);

    // return `true` if the node should be reported to Lokid as being
    // reachable or unreachable for a long time depending on `type`
    bool should_report_as(const sn_pub_key_t& sn, ReportType type);

    // Expires a node, removing it from offline nodes.  Returns true if found
    // and removed, false if it didn't exist.
    bool expire(const sn_pub_key_t& sn);

    void set_reported(const sn_pub_key_t& sn);

    // Retrun the least recently tested node
    std::optional<sn_pub_key_t> next_to_test();
};

} // namespace loki
