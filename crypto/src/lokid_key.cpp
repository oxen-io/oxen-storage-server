#include "lokid_key.h"
#include "utils.hpp"
extern "C" {
#include "sodium/private/ed25519_ref10.h"
}

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <sodium.h>

#include <exception>
#include <fstream>
#include <iterator>

namespace fs = boost::filesystem;

namespace loki {

private_key_t lokidKeyFromHex(const std::string& private_key_hex) {
    if (private_key_hex.size() != KEY_LENGTH * 2)
        throw std::runtime_error(
                "Lokid key data is invalid: expected " + std::to_string(KEY_LENGTH) + " bytes not " +
                std::to_string(private_key_hex.size()) + " bytes");

    const auto bytes = util::hex_to_bytes(private_key_hex);
    private_key_t private_key;
    std::copy(bytes.begin(), bytes.end(), private_key.begin());

    return private_key;
}

public_key_t derive_pubkey_legacy(const private_key_t& private_key) {
    ge25519_p3 A;
    ge25519_scalarmult_base(&A, private_key.data());
    public_key_t publicKey;
    ge25519_p3_tobytes(publicKey.data(), &A);

    return publicKey;
}


public_key_t derive_pubkey_x25519(const private_key_t& seckey) {

    public_key_t pubkey;
    crypto_scalarmult_base(pubkey.data(), seckey.data());

    return pubkey;
}

} // namespace loki
