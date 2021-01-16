#pragma once

#include "oxen_common.h"
#include <atomic>
#include <deque>
#include <unordered_map>

namespace oxen {

struct time_entry_t {
    time_t timestamp;
};

enum class ResultType { OK, MISMATCH, OTHER, REJECTED };

struct test_result_t {

    // seconds since Epoch when entry was recorded
    time_t timestamp;
    ResultType result;
};

inline const char* to_str(ResultType result) {
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

    std::deque<test_result_t> blockchain_tests;
};

class all_stats_t {

    // ===== This node's stats =====
    uint64_t total_client_store_requests = 0;
    // Number of requests in the latest x min interval
    uint64_t previous_period_store_requests = 0;
    // Number of requests after the latest x min interval
    uint64_t recent_store_requests = 0;

    uint64_t total_client_retrieve_requests = 0;
    // Number of requests in the latest x min interval
    uint64_t previous_period_retrieve_requests = 0;
    // Number of requests after the latest x min interval
    uint64_t recent_retrieve_requests = 0;

    uint64_t previous_period_proxy_requests = 0;
    std::atomic<uint64_t> recent_proxy_requests{0};

    uint64_t previous_period_onion_requests = 0;
    std::atomic<uint64_t> recent_onion_requests{0};

    time_point_t reset_time_ = std::chrono::steady_clock::now();
    // =============================

    /// update period moving recent request counters to
    /// the `previous period`
    void next_period() {
        previous_period_store_requests = recent_store_requests;
        previous_period_retrieve_requests = recent_retrieve_requests;
        previous_period_proxy_requests = recent_proxy_requests.load();
        previous_period_onion_requests = recent_onion_requests.load();
        recent_store_requests = 0;
        recent_retrieve_requests = 0;
        recent_proxy_requests = 0;
        recent_onion_requests = 0;
    }

  public:
    // stats per every peer in our swarm (including former peers)
    std::unordered_map<sn_record_t, peer_stats_t> peer_report_;

    void record_request_failed(const sn_record_t& sn) {
        peer_report_[sn].requests_failed++;
    }

    void record_push_failed(const sn_record_t& sn) {
        peer_report_[sn].pushes_failed++;
    }

    void record_storage_test_result(const sn_record_t& sn, ResultType result) {
        test_result_t res = {std::time(nullptr), result};
        peer_report_[sn].storage_tests.push_back(res);
    }

    void record_blockchain_test_result(const sn_record_t& sn,
                                       ResultType result) {
        test_result_t t = {std::time(nullptr), result};
        peer_report_[sn].blockchain_tests.push_back(t);
    }

    // remove old test entries and reset counters, update reset time
    void cleanup();

    void bump_proxy_requests() { recent_proxy_requests++; }

    void bump_onion_requests() { recent_proxy_requests++; }

    void bump_store_requests() {
        total_client_store_requests++;
        recent_store_requests++;
    }

    void bump_retrieve_requests() {
        total_client_retrieve_requests++;
        recent_retrieve_requests++;
    }

    uint64_t get_total_store_requests() const {
        return total_client_store_requests;
    }

    uint64_t get_recent_store_requests() const { return recent_store_requests; }

    uint64_t get_recent_proxy_requests() const { return recent_proxy_requests; }

    uint64_t get_previous_period_proxy_requests() const {
        return previous_period_proxy_requests;
    }

    uint64_t get_recent_onion_requests() const { return recent_onion_requests; }

    uint64_t get_previous_period_onion_requests() const {
        return previous_period_onion_requests;
    }

    uint64_t get_previous_period_store_requests() const {
        return previous_period_store_requests;
    }

    uint64_t get_total_retrieve_requests() const {
        return total_client_retrieve_requests;
    }

    uint64_t get_recent_retrieve_requests() const {
        return recent_retrieve_requests;
    }

    uint64_t get_previous_period_retrieve_requests() const {
        return previous_period_retrieve_requests;
    }

    time_point_t get_reset_time() const { return reset_time_; }
};

} // namespace oxen
