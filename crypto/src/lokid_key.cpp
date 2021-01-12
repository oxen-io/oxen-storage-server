#include "lokid_key.h"
#include "utils.hpp"

#include <sodium.h>
#include <lokimq/hex.h>

#include <exception>
#include <fstream>
#include <iterator>

namespace loki {

private_key_t lokidKeyFromHex(const std::string& private_key_hex) {
    if (!lokimq::is_hex(private_key_hex) || private_key_hex.size() != KEY_LENGTH * 2)
        throw std::runtime_error("Lokid key data is invalid: expected " +
                                 std::to_string(KEY_LENGTH) + " hex digits not " +
                                 std::to_string(private_key_hex.size()) +
                                 " bytes");

    private_key_t private_key;
    lokimq::from_hex(private_key_hex.begin(), private_key_hex.end(), private_key.begin());

    return private_key;
}

private_key_ed25519_t
private_key_ed25519_t::from_hex(const std::string& sc_hex) {
    if (sc_hex.size() != private_key_ed25519_t::LENGTH * 2)
        throw std::runtime_error("Lokid key data is invalid: expected " +
                                 std::to_string(private_key_ed25519_t::LENGTH) +
                                 " hex digits not " + std::to_string(sc_hex.size()) +
                                 " bytes");

    private_key_ed25519_t key;
    lokimq::from_hex(sc_hex.begin(), sc_hex.end(), key.data.begin());

    return key;
}

public_key_t derive_pubkey_legacy(const private_key_t& private_key) {
    public_key_t publicKey;
    crypto_scalarmult_ed25519_base_noclamp(publicKey.data(),
                                           private_key.data());

    return publicKey;
}

public_key_t derive_pubkey_x25519(const private_key_t& seckey) {

    public_key_t pubkey;
    crypto_scalarmult_curve25519_base(pubkey.data(), seckey.data());

    return pubkey;
}

public_key_t derive_pubkey_ed25519(const private_key_ed25519_t& seckey) {

    public_key_t pubkey;
    crypto_sign_ed25519_sk_to_pk(pubkey.data(), seckey.data.data());

    return pubkey;
}

std::string key_to_string(const std::array<uint8_t, loki::KEY_LENGTH>& key) {
    auto pk = reinterpret_cast<const char*>(&key);
    return std::string{pk, loki::KEY_LENGTH};
}

} // namespace loki
