
#include "loki_logger.h"
#include "reachability_testing.h"

using std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace loki {

namespace detail {

reach_record_t::reach_record_t() {
    this->first_failure = steady_clock::now();
    this->last_tested = this->first_failure;
}

} // namespace detail

/// How long to wait until reporting unreachable nodes to Lokid
constexpr std::chrono::minutes UNREACH_GRACE_PERIOD = 120min;

bool reachability_records_t::record_unreachable(const sn_pub_key_t& sn) {

    auto it = offline_nodes_.find(sn);

    if (it == offline_nodes_.end()) {
        LOKI_LOG(info, "adding a new node to UNREACHABLE: {}", sn);
        offline_nodes_.insert({sn, {}});
    } else {
        LOKI_LOG(info, "node is ALREAY known to be UNREACHABLE: {}", sn);

        it->second.last_tested = steady_clock::now();

        const auto elapsed = it->second.last_tested - it->second.first_failure;
        const auto elapsed_sec =
            std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        LOKI_LOG(info, "    - first time failed {} seconds ago", elapsed_sec);

        /// TODO: Might still want to report as unreachable since this status
        /// gets reset to `true` on Lokid restart
        if (elapsed > UNREACH_GRACE_PERIOD && !it->second.reported) {
            LOKI_LOG(warn, "    - will REPORT this node to Lokid!");
            return true;
        } else {
            if (it->second.reported) {
                LOKI_LOG(warn, "    - Already reported node: {}", sn);
            }
        }
    }

    return false;
}

bool reachability_records_t::record_reachable(const sn_pub_key_t& sn) {
    expire(sn);
}

bool reachability_records_t::expire(const sn_pub_key_t& sn) {

    if (offline_nodes_.erase(sn)) {
        LOKI_LOG(warn, "    - removed entry for {}", sn);
    }

}

void reachability_records_t::set_reported(const sn_pub_key_t& sn) {

    auto it = offline_nodes_.find(sn);
    if (it != offline_nodes_.end()) {
        it->second.reported = true;
    }
}

boost::optional<sn_pub_key_t> reachability_records_t::next_to_test() {

    const auto it = std::min_element(
        offline_nodes_.begin(), offline_nodes_.end(),
        [&](const auto& lhs, const auto& rhs) {
            return lhs.second.last_tested < rhs.second.last_tested;
        });

    if (it == offline_nodes_.end()) {
        return boost::none;
    } else {

        LOKI_LOG(warn, "~~~ Selecting to be re-tested: {}", it->first);

        return it->first;
    }
}

} // namespace loki
