#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <oxenss/crypto/keys.h>

namespace oxenss::snode {

struct sn_record {
    std::string ip;
    uint16_t port{0};
    uint16_t omq_quic_port{0};  // Same port for both: quic is UDP, OMQ is TCP
    crypto::legacy_pubkey pubkey_legacy{};
    crypto::ed25519_pubkey pubkey_ed25519{};
    crypto::x25519_pubkey pubkey_x25519{};
};

// Returns true if two sn_record's refer to the same snode (i.e. have the same legacy pubkey).
// Note that other fields/pubkeys are not checked.
inline bool operator==(const sn_record& lhs, const sn_record& rhs) {
    return lhs.pubkey_legacy == rhs.pubkey_legacy;
}
// Returns true if two sn_record's have different pubkey_legacy values.
inline bool operator!=(const sn_record& lhs, const sn_record& rhs) {
    return !(lhs == rhs);
}

struct sn_test {
    const snode::sn_record sn;
    std::function<void(const snode::sn_record, bool passed)> finished;
    std::atomic<int> remaining;
    std::atomic<bool> failed{false};

    sn_test(const snode::sn_record& sn,
            int test_count,
            std::function<void(const snode::sn_record&, bool passed)> finished) :
            sn{sn}, finished{std::move(finished)}, remaining{test_count} {}

    void add_result(bool pass) {
        if (!pass)
            failed = true;
        if (--remaining == 0)
            finished(sn, pass && !failed);
    }
};

}  // namespace oxenss::snode
