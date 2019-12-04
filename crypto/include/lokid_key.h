#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace loki {

constexpr size_t KEY_LENGTH = 32;
using public_key_t = std::array<uint8_t, KEY_LENGTH>;
using private_key_t = std::array<uint8_t, KEY_LENGTH>;

struct lokid_key_pair_t {
    private_key_t private_key;
    public_key_t public_key;
};

private_key_t lokidKeyFromHex(const std::string& private_key_hex);

public_key_t calcPublicKey(const private_key_t& private_key);

} // namespace loki
