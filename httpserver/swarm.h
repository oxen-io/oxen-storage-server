#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "loki_common.h"

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

struct block_update_t {
    all_swarms_t swarms;
    uint64_t height;
    std::string block_hash;
    int hardfork;
};

swarm_id_t get_swarm_by_pk(const std::vector<SwarmInfo>& all_swarms,
                           const std::string& pk);

struct SwarmEvents {

    /// our (potentially new) swarm id
    swarm_id_t our_swarm_id;
    /// whether our swarm got decommissioned and we
    /// need to salvage our stale data
    bool decommissioned = false;
    /// detected new swarms that need to be bootstrapped
    std::vector<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::vector<sn_record_t> new_snodes;
    /// our swarm members 
    std::vector<sn_record_t> our_swarm_members;
};

class Swarm {

    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;
    std::vector<SwarmInfo> all_cur_swarms_;
    sn_record_t our_address_;
    std::vector<sn_record_t> swarm_peers_;

  public:
    Swarm(sn_record_t address) : our_address_(address) {}

    ~Swarm();

    /// Extract relevant information from incoming swarm composition
    SwarmEvents derive_swarm_events(const all_swarms_t& swarms) const;

    /// Update swarm state according to `events`
    void update_state(const all_swarms_t& swarms, const SwarmEvents& events);

    void apply_swarm_changes(const all_swarms_t& new_swarms);

    bool is_pubkey_for_us(const std::string& pk) const;

    const std::vector<sn_record_t>& other_nodes() const;

    const std::vector<SwarmInfo>& all_swarms() const { return all_cur_swarms_; }

    swarm_id_t our_swarm_id() const { return cur_swarm_id_; }

    bool is_valid() const { return cur_swarm_id_ != INVALID_SWARM_ID; }

    void set_swarm_id(swarm_id_t sid);
};

} // namespace loki
