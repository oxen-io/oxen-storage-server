#pragma once

#include <cstdint>
#include <string>

#include "oxend_key.h"

namespace oxen {

struct sn_record_t {
    std::string ip;
    uint16_t port{0};
    uint16_t lmq_port{0};
    legacy_pubkey pubkey_legacy{};
    ed25519_pubkey pubkey_ed25519{};
    x25519_pubkey pubkey_x25519{};
};

// Returns true if two sn_record_t's refer to the same snode (i.e. have the same legacy pubkey).
// Note that other fields/pubkeys are not checked.
inline bool operator==(const sn_record_t& lhs, const sn_record_t& rhs) {
    return lhs.pubkey_legacy == rhs.pubkey_legacy;
}
// Returns true if two sn_record_t's have different pubkey_legacy values.
inline bool operator!=(const sn_record_t& lhs, const sn_record_t& rhs) {
    return !(lhs == rhs);
}

}
