#pragma once

#include "oxen_common.h"
#include "sn_record.h"

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace oxenmq { class OxenMQ; }

namespace oxen {

// How often we clean up and rotate previous stats windows
inline constexpr std::chrono::seconds STATS_CLEANUP_INTERVAL = 10min;

// How many previous stats windows we keep; each window represents the counts between stats cleanup
// calls; by keeping several we keep our recent stats at a rolling average of at least
// STATS_WINDOWS*STATS_CLEANUP_INTERVAL plus however long since the last cleanup.
inline constexpr size_t RECENT_STATS_COUNT = 6;

struct time_entry_t {
    time_t timestamp;
};

enum class ResultType { OK, MISMATCH, OTHER, REJECTED };

struct test_result_t {
    std::chrono::system_clock::time_point timestamp;
    ResultType result;
};

inline constexpr const char* to_str(ResultType result) {
    switch (result) {
    case ResultType::OK:
        return "OK";
    case ResultType::MISMATCH:
        return "MISMATCH";
    case ResultType::REJECTED:
        return "REJECTED";
    case ResultType::OTHER:
    default:
        return "OTHER";
    }
}

// Stats per peer
struct peer_stats_t {

    // how many times a single request failed
    uint64_t requests_failed = 0;
    // how many times a series of push requests failed
    // causing this node to give up re-transmitting
    uint64_t pushes_failed = 0;

    std::deque<test_result_t> storage_tests;
};

struct period_stats {
    uint64_t
        client_store_requests = 0,
        client_retrieve_requests = 0,
        proxy_requests = 0,
        onion_requests = 0;
};

class all_stats_t {

    // ===== This node's stats =====
    std::atomic<uint64_t>
        total_client_store_requests{0},
        current_client_store_requests{0},
        total_client_retrieve_requests{0},
        current_client_retrieve_requests{0},
        total_proxy_requests{0},
        current_proxy_requests{0},
        total_onion_requests{0},
        current_onion_requests{0};

    // Rolling stats for the previous N periods; each time we call cleanup (i.e. every 10 minutes)
    // we rotate these, keeping the most recent 5.  Thus we can determine stats for (approximately)
    // the last hour by using these 5 historical values + the current_... values above.
    std::deque<std::pair<std::chrono::steady_clock::time_point, period_stats>> previous_stats;
    std::chrono::steady_clock::time_point last_rotate = std::chrono::steady_clock::now();
    mutable std::mutex prev_stats_mutex;

    // stats per every peer in our swarm (including former peers)
    std::unordered_map<legacy_pubkey, peer_stats_t> peer_report_;
    mutable std::mutex peer_report_mutex;

    // remove old test entries and reset counters, update reset time
    void cleanup();

  public:
    explicit all_stats_t(oxenmq::OxenMQ& omq);

    // Returns the number of failed requests for the given pubkey over the last ROLLING_WINDOW
    void record_request_failed(const legacy_pubkey& sn) {
        std::lock_guard lock{peer_report_mutex};
        peer_report_[sn].requests_failed++;
    }

    // Returns the number of failed pushes for the given pubkey over the last ROLLING_WINDOW
    void record_push_failed(const legacy_pubkey& sn) {
        std::lock_guard lock{peer_report_mutex};
        peer_report_[sn].pushes_failed++;
    }

    // Records a storage test result for the given peer
    void record_storage_test_result(const legacy_pubkey& sn, ResultType result) {
        std::lock_guard lock{peer_report_mutex};
        peer_report_[sn].storage_tests.push_back({std::chrono::system_clock::now(), result});
    }

    // Returns a copy of the current peer report
    std::unordered_map<legacy_pubkey, peer_stats_t> peer_report() const {
        std::lock_guard lock{peer_report_mutex};
        return peer_report_;
    }

    void bump_proxy_requests() {
        total_proxy_requests++;
        current_proxy_requests++;
    }
    void bump_onion_requests() {
        total_onion_requests++;
        current_onion_requests++;
    }
    void bump_store_requests() {
        total_client_store_requests++;
        current_client_store_requests++;
    }
    void bump_retrieve_requests() {
        total_client_retrieve_requests++;
        current_client_retrieve_requests++;
    }

    uint64_t get_total_proxy_requests() const { return total_proxy_requests; }
    uint64_t get_total_onion_requests() const { return total_onion_requests; }
    uint64_t get_total_store_requests() const { return total_client_store_requests; }
    uint64_t get_total_retrieve_requests() const { return total_client_retrieve_requests; }

    /// Retrieves recent request counts using current period + stored previous period counts.
    ///
    /// Returns the time window (*not* the timestamp) of the returned stats and the stats.
    std::pair<std::chrono::steady_clock::duration, period_stats> get_recent_requests() const;
};

} // namespace oxen
