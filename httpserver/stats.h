#pragma once

#include "loki_common.h"
#include <ctime>
#include <deque>
#include <unordered_map>

namespace loki {

struct time_entry_t {
    time_t timestamp;
};

struct test_result_t {
    // seconds since Epoch when entry was recorded
    time_t timestamp;
    bool success;
};

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

    // stats per every peer in our swarm (including former peers)
    std::unordered_map<sn_record_t, peer_stats_t> peer_report_;

  public:
    // ===== This node's stats =====
    uint64_t client_store_requests = 0;
    uint64_t client_retrieve_requests = 0;

    time_t reset_time = time(nullptr);

    // =============================

    void record_request_failed(const sn_record_t& sn) {
        peer_report_[sn].requests_failed++;
    }

    void record_push_failed(const sn_record_t& sn) {
        peer_report_[sn].pushes_failed++;
    }

    void record_storage_test_result(const sn_record_t& sn, bool success) {
        test_result_t res = {std::time(nullptr), success};
        peer_report_[sn].storage_tests.push_back(res);
    }

    void record_blockchain_test_result(const sn_record_t& sn, bool success) {
        test_result_t t = {std::time(nullptr), success};
        peer_report_[sn].blockchain_tests.push_back(t);
    }

    // remove old test entries and reset counters, update reset time
    void cleanup();

    // Convert to a string, add indentations if pretty
    std::string to_json(bool pretty) const;
};

} // namespace loki
