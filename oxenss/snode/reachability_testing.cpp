
#include "reachability_testing.h"
#include "oxenss/crypto/keys.h"
#include "swarm.h"
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/random.hpp>

#include <chrono>

namespace oxenss::snode {

static auto logcat = log::Cat("snode");

using fseconds = std::chrono::duration<float, std::chrono::seconds::period>;
using fminutes = std::chrono::duration<float, std::chrono::minutes::period>;

static void check_incoming_tests_impl(
        std::string_view name,
        const reachability_testing::clock::time_point& now,
        const reachability_testing::clock::time_point& startup,
        detail::incoming_test_state& incoming) {
    const auto elapsed = now - std::max(startup, incoming.last_test);
    bool failing = elapsed > reachability_testing::MAX_TIME_WITHOUT_PING;
    bool whine = failing != incoming.was_failing ||
                 (failing && now - incoming.last_whine > reachability_testing::WHINING_INTERVAL);

    incoming.was_failing = failing;

    if (whine) {
        incoming.last_whine = now;
        if (!failing) {
            log::info(logcat, "{} ping received; port is likely reachable again", name);
        } else {
            if (incoming.last_test.time_since_epoch() == 0s) {
                log::warning(logcat, "Have NEVER received {} pings!", name);
            } else {
                log::warning(
                        logcat,
                        "Have not received {} pings for a long time ({:.1f} mins)!",
                        name,
                        fminutes{elapsed}.count());
            }
            log::warning(
                    logcat,
                    "Please check your {} port. Not being reachable "
                    "over {} may result in a deregistration!",
                    name,
                    name);
        }
    }
}

void reachability_testing::check_incoming_tests(const clock::time_point& now) {
    check_incoming_tests_impl("HTTP", now, startup, last_https);
    check_incoming_tests_impl("OxenMQ", now, startup, last_omq);
    check_incoming_tests_impl("QUIC", now, startup, last_quic);
}

void reachability_testing::incoming_ping(ReachType type, const clock::time_point& now) {
    (type == ReachType::OMQ    ? last_omq
     : type == ReachType::QUIC ? last_quic
                               : last_https)
            .last_test = now;
}

std::optional<crypto::legacy_pubkey> reachability_testing::next_random(
        const Swarm& swarm, const clock::time_point& now, bool requeue) {
    if (next_general_test > now)
        return std::nullopt;
    next_general_test = now + std::chrono::duration_cast<clock::duration>(
                                      fseconds(TESTING_INTERVAL(util::rng())));

    // Pull the next element off the queue, but skip ourself, any that are no longer registered,
    // and any that are currently known to be failing (those are queued for testing separately).
    while (!testing_queue.empty()) {
        auto& pk = testing_queue.back();
        std::optional<crypto::legacy_pubkey> sn;
        if (pk != swarm.our_pk && !failing.count(pk))
            sn = pk;
        testing_queue.pop_back();
        if (sn)
            return sn;
    }
    if (!requeue)
        return std::nullopt;

    // FIXME: when a *new* node comes online we ought to inject it into a random position in the
    // SN list with probability (L/N) [L = current list size, N = potential list size]
    //
    // (FIXME: put this FIXME in a better place ;-) )

    // We exhausted the queue so repopulate it and try again

    auto all = swarm.network.contacts.get_pubkeys();
    testing_queue.reserve(all.size());
    testing_queue.assign(all.begin(), all.end());

    std::shuffle(testing_queue.begin(), testing_queue.end(), util::rng());

    return next_random(swarm, now, false /*= dont recurse again*/);
}

std::vector<std::pair<crypto::legacy_pubkey, int>> reachability_testing::get_failing(
        clock::time_point now) {
    // Our failing_queue puts the oldest retest times at the top, so pop them off into our
    // result until the top node should be retested sometime in the future
    std::vector<std::pair<crypto::legacy_pubkey, int>> result;
    while (result.size() < MAX_RETESTS_PER_TICK && !failing_queue.empty()) {
        auto& [pk, retest_time, failures] = failing_queue.top();
        if (retest_time > now)
            break;
        result.emplace_back(pk, failures);
        failing_queue.pop();
    }
    return result;
}

void reachability_testing::add_failing_node(
        const crypto::legacy_pubkey& pk, int previous_failures) {
    using namespace std::chrono;

    if (previous_failures < 0)
        previous_failures = 0;
    auto next_test_in = duration_cast<clock::duration>(
            previous_failures * TESTING_BACKOFF + fseconds{TESTING_INTERVAL(util::rng())});
    if (next_test_in > TESTING_BACKOFF_MAX)
        next_test_in = TESTING_BACKOFF_MAX;

    failing.insert(pk);
    failing_queue.emplace(pk, steady_clock::now() + next_test_in, previous_failures + 1);
}

void reachability_testing::remove_node_from_failing(const crypto::legacy_pubkey& pk) {
    failing.erase(pk);
}

}  // namespace oxenss::snode
