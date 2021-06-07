
#include "reachability_testing.h"
#include "oxen_logger.h"
#include "swarm.h"
#include "utils.hpp"
#include <chrono>

using std::chrono::steady_clock;

namespace oxen {

using fseconds = std::chrono::duration<float, std::chrono::seconds::period>;
using fminutes = std::chrono::duration<float, std::chrono::minutes::period>;

static void check_incoming_tests_impl(
        std::string_view name,
        const time_point_t& now,
        const time_point_t& startup,
        detail::incoming_test_state& incoming) {

    const auto elapsed = now - std::max(startup, incoming.last_test);
    bool failing = elapsed > reachability_testing::MAX_TIME_WITHOUT_PING;
    bool whine = failing != incoming.was_failing ||
        (failing && now - incoming.last_whine > reachability_testing::WHINING_INTERVAL);

    incoming.was_failing = failing;

    if (whine) {
        incoming.last_whine = now;
        if (!failing) {
            OXEN_LOG(info, "{} ping received; port is likely reachable again", name);
        } else {
            if (incoming.last_test.time_since_epoch() == 0s) {
                OXEN_LOG(warn, "Have NEVER received {} pings!", name);
            } else {
                OXEN_LOG(warn,
                    "Have not received {} pings for a long time ({:.1f} mins)!",
                    name, fminutes{elapsed}.count());
            }
            OXEN_LOG(warn, "Please check your {} port. Not being reachable "
                    "over {} may result in a deregistration!", name, name);
        }
    }
}

void reachability_testing::check_incoming_tests(const time_point_t& now) {
    check_incoming_tests_impl("HTTP", now, startup, last_https);
    check_incoming_tests_impl("OxenMQ", now, startup, last_omq);
}

void reachability_testing::incoming_ping(ReachType type, const time_point_t& now) {
    (type == ReachType::OMQ ? last_omq : last_https).last_test = now;
}

std::optional<sn_record_t> reachability_testing::next_random(
        const Swarm& swarm,
        const time_point_t& now,
        bool requeue) {

    if (next_general_test > now)
        return std::nullopt;
    next_general_test = now + std::chrono::duration_cast<time_point_t::duration>(
            fseconds(TESTING_INTERVAL(util::rng())));

    // Pull the next element off the queue, but skip ourself, any that are no longer registered, and
    // any that are currently known to be failing (those are queued for testing separately).
    auto& my_pk = swarm.our_address().pubkey_legacy;
    while (!testing_queue.empty()) {
        auto& pk = testing_queue.back();
        std::optional<sn_record_t> sn;
        if (pk != my_pk && !failing.count(pk))
            sn = swarm.find_node(pk);
        testing_queue.pop_back();
        if (sn)
            return sn;
    }
    if (!requeue)
        return std::nullopt;

    // FIXME: when a *new* node comes online we need to inject it into a random position in the SN
    // list with probability (L/N) [L = current list size, N = potential list size]
    //
    // (FIXME: put this FIXME in a better place ;-) )

    // We exhausted the queue so repopulate it and try again

    auto& all = swarm.all_funded_nodes();
    testing_queue.reserve(all.size());

    for (const auto& [pk, _sn] : all)
        testing_queue.push_back(pk);

    std::shuffle(testing_queue.begin(), testing_queue.end(), util::rng());

    // Recurse with the rebuild list, but don't let it try rebuilding again
    return next_random(swarm, now, false);
}

std::vector<std::pair<sn_record_t, int>> reachability_testing::get_failing(
        const Swarm& swarm,
        const time_point_t& now) {
    // Our failing_queue puts the oldest retest times at the top, so pop them off into our result
    // until the top node should be retested sometime in the future
    std::vector<std::pair<sn_record_t, int>> result;
    while (result.size() < MAX_RETESTS_PER_TICK && !failing_queue.empty()) {
        auto& [pk, retest_time, failures] = failing_queue.top();
        if (retest_time > now)
            break;
        if (auto sn = swarm.find_node(pk))
            result.emplace_back(std::move(*sn), failures);
        failing.erase(pk);
        failing_queue.pop();
    }
    return result;
}

void reachability_testing::add_failing_node(const legacy_pubkey& pk, int previous_failures) {
    using namespace std::chrono;

    if (previous_failures < 0) previous_failures = 0;
    auto next_test_in = duration_cast<time_point_t::duration>(
            previous_failures * TESTING_BACKOFF + fseconds{TESTING_INTERVAL(util::rng())});
    if (next_test_in > TESTING_BACKOFF_MAX)
        next_test_in = TESTING_BACKOFF_MAX;

    failing.insert(pk);
    failing_queue.emplace(pk, steady_clock::now() + next_test_in, previous_failures + 1);
}

} // namespace oxen
