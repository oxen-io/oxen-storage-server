#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "common.h"

namespace boost {
namespace asio {
class io_context;
}
} // namespace boost

namespace loki {

class ServiceNode;

struct SwarmInfo {
    swarm_id_t swarm_id;
    std::vector<sn_record_t> snodes;
};

using all_swarms_t = std::vector<SwarmInfo>;

swarm_id_t get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms,
                           const std::string& pk);

struct SwarmEvents {

    /// whether our swarm got decommissioned and we
    /// need to salvage our stale data
    bool decommissioned = false;
    /// detected new swarms that need to be bootstrapped
    std::vector<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::vector<sn_record_t> new_snodes;
};

class Swarm {

    swarm_id_t cur_swarm_id_ = UINT64_MAX;
    std::vector<SwarmInfo> all_cur_swarms_;
    sn_record_t our_address_;
    std::vector<sn_record_t> swarm_peers_;

  public:
    Swarm(sn_record_t address) : our_address_(address) {}

    ~Swarm();

    /// Update swarms and work out the changes
    SwarmEvents update_swarms(const all_swarms_t& swarms);

    bool is_pubkey_for_us(const std::vector<SwarmInfo>& all_swarms,
                          const std::string& pk) const;

    const std::vector<sn_record_t>& other_nodes() const;

    const std::vector<SwarmInfo>& all_swarms() const { return all_cur_swarms_; }

    swarm_id_t our_swarm_id() const { return cur_swarm_id_; }
};

} // namespace loki
