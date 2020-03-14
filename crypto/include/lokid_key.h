#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace loki {

constexpr size_t KEY_LENGTH = 32;
using public_key_t = std::array<uint8_t, KEY_LENGTH>;
using private_key_t = std::array<uint8_t, KEY_LENGTH>;

struct private_key_ed25519_t {
    static constexpr uint32_t LENGTH = 64;
    std::array<uint8_t, private_key_ed25519_t::LENGTH> data;
    static private_key_ed25519_t from_hex(const std::string& sc_hex);
};


struct lokid_key_pair_t {
    private_key_t private_key;
    public_key_t public_key;
};

std::string key_to_string(const std::array<uint8_t, loki::KEY_LENGTH>& key);

private_key_t lokidKeyFromHex(const std::string& private_key_hex);

public_key_t derive_pubkey_legacy(const private_key_t& private_key);
public_key_t derive_pubkey_x25519(const private_key_t& private_key);
public_key_t derive_pubkey_ed25519(const private_key_ed25519_t& private_key);

} // namespace loki
