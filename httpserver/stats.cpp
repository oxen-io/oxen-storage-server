#include "stats.h"
#include <algorithm>
#include <chrono>
#include <iostream>

#include <oxenmq/oxenmq.h>
#include <unordered_map>

namespace oxen {
all_stats_t::all_stats_t(oxenmq::OxenMQ& omq) {
    omq.add_timer([this] { cleanup(); }, STATS_CLEANUP_INTERVAL);
}

static void cleanup_old(
        std::deque<test_result>& tests, std::chrono::system_clock::time_point cutoff_time) {
    while (!tests.empty() && tests.front().timestamp <= cutoff_time)
        tests.pop_front();
}

static constexpr auto ROLLING_WINDOW = 120min;

void all_stats_t::cleanup() {
    {
        // rotate historic period counters
        std::lock_guard lock{prev_stats_mutex};
        while (previous_stats.size() >= RECENT_STATS_COUNT)
            previous_stats.pop_front();
        previous_stats.emplace_back(
                last_rotate,
                period_stats{
                        current_client_store_requests.exchange(0),
                        current_client_retrieve_requests.exchange(0),
                        current_proxy_requests.exchange(0),
                        current_onion_requests.exchange(0)});
        last_rotate = std::chrono::steady_clock::now();
    }

    {
        // Clean up old peer report stats
        std::lock_guard lock{peer_report_mutex};

        const auto cutoff = std::chrono::system_clock::now() - ROLLING_WINDOW;
        for (auto& [kv, stats] : peer_report_)
            cleanup_old(stats.storage_tests, cutoff);
    }
}

std::pair<std::chrono::steady_clock::duration, period_stats> all_stats_t::get_recent_requests()
        const {
    std::pair<std::chrono::steady_clock::duration, period_stats> result;
    auto& [window, stats] = result;

    std::lock_guard lock{prev_stats_mutex};
    window = std::chrono::steady_clock::now() -
             (previous_stats.empty() ? last_rotate : previous_stats.front().first);

    stats = {
            current_client_store_requests,
            current_client_retrieve_requests,
            current_proxy_requests,
            current_onion_requests};
    for (auto& [ts, ps] : previous_stats) {
        stats.client_store_requests += ps.client_store_requests;
        stats.client_retrieve_requests += ps.client_retrieve_requests;
        stats.proxy_requests += ps.proxy_requests;
        stats.onion_requests += ps.onion_requests;
    }

    return result;
}

}  // namespace oxen
