#pragma once

#include "loki_common.h"
#include <chrono>
#include <unordered_map>

namespace loki {

namespace detail {

/// TODO: make this class "private"?
class reach_record_t {

    // The time the node failed for the first time
    // (and hasn't come back online)

    using time_point_t = std::chrono::time_point<std::chrono::steady_clock>;

  public:
    time_point_t first_failure;
    time_point_t last_tested;
    // whether it's been reported to Lokid
    bool reported = false;

    reach_record_t();
};
} // namespace detail

class reachability_records_t {

    // TODO: sn_records are heavy (3 strings), so how about we only store the
    // pubkey?

    // Nodes that failed the reachability test
    // Note: I don't expect this list to be large, so
    // `std::vector` is probably faster than `std::set` here
    std::unordered_map<sn_pub_key_t, detail::reach_record_t> offline_nodes_;

  public:
    // Return nodes that should be tested first: decommissioned nodes
    // and those that failed our earlier tests (but not reported yet)
    // std::vector<> priority_nodes() const;

    // Records node as unreachable, return `true` if the node should be
    // reported to Lokid as being unreachable for a long time
    bool record_unreachable(const sn_pub_key_t& sn);

    bool record_reachable(const sn_pub_key_t& sn);

    bool expire(const sn_pub_key_t& sn);

    void set_reported(const sn_pub_key_t& sn);

    // Retrun the least recently tested node
    boost::optional<sn_pub_key_t> next_to_test();
};

} // namespace loki
