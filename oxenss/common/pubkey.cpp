#include "pubkey.h"
#include "mainnet.h"
#include <cstdint>
#include <oxenc/hex.h>
#include <charconv>
#include <cassert>

namespace oxen {

user_pubkey& user_pubkey::load(std::string_view pk) {
    if (pk.size() == USER_PUBKEY_SIZE_HEX && oxenc::is_hex(pk)) {
        uint8_t netid;
        oxenc::from_hex(pk.begin(), pk.begin() + 2, &netid);
        network_ = netid;
        pubkey_ = oxenc::from_hex(pk.substr(2));
    } else if (pk.size() == USER_PUBKEY_SIZE_BYTES) {
        network_ = static_cast<uint8_t>(pk.front());
        pubkey_ = pk.substr(1);
    } else if (!is_mainnet && pk.size() == USER_PUBKEY_SIZE_HEX - 2 && oxenc::is_hex(pk)) {
        network_ = 5;
        pubkey_ = oxenc::from_hex(pk);
    } else if (!is_mainnet && pk.size() == USER_PUBKEY_SIZE_BYTES - 1) {
        network_ = 5;
        pubkey_ = pk;
    } else {
        network_ = -1;
        pubkey_.clear();
    }
    return *this;
}

std::string user_pubkey::hex() const {
    return oxenc::to_hex(pubkey_);
}

std::string user_pubkey::prefixed_hex() const {
    std::string hex;
    if (pubkey_.empty())
        return hex;
    hex.reserve(USER_PUBKEY_SIZE_HEX);
    auto bi = std::back_inserter(hex);
    if (uint8_t netid = type(); !(netid == 0 && !is_mainnet))
        oxenc::to_hex(&netid, &netid + 1, bi);
    oxenc::to_hex(pubkey_.begin(), pubkey_.end(), bi);
    return hex;
}

std::string user_pubkey::prefixed_raw() const {
    std::string bytes;
    if (pubkey_.empty())
        return bytes;
    bytes.reserve(1 + USER_PUBKEY_SIZE_BYTES);
    bytes += static_cast<uint8_t>(network_);
    bytes += pubkey_;
    return bytes;
}

}  // namespace oxen
