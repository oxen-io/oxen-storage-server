#pragma once

#include <atomic>
#include <functional>

#include <oxenss/crypto/keys.h>

namespace oxenss::snode {

struct sn_test {
    crypto::legacy_pubkey pubkey{};
    std::function<void(const crypto::legacy_pubkey&, bool passed)> finished;
    std::atomic<int> remaining;
    std::atomic<bool> failed{false};

    sn_test(const crypto::legacy_pubkey& sn,
            int test_count,
            std::function<void(const crypto::legacy_pubkey&, bool passed)> finished) :
            pubkey{sn}, finished{std::move(finished)}, remaining{test_count} {}

    void add_result(bool pass) {
        if (!pass)
            failed = true;
        if (--remaining == 0)
            finished(pubkey, pass && !failed);
    }
};

}  // namespace oxenss::snode
