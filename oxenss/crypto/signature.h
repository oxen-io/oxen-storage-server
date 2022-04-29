#pragma once

#include "keys.h"

#include <array>

namespace oxen::crypto {

constexpr size_t HASH_SIZE = 32;
constexpr size_t EC_SCALAR_SIZE = 32;

using hash = std::array<unsigned char, HASH_SIZE>;
using ec_scalar = std::array<unsigned char, EC_SCALAR_SIZE>;

struct signature {
    ec_scalar c, r;

    // Decodes a base64 signature into a `signature`.  Throws on invalid input.
    static signature from_base64(std::string_view b64);
};

// Returns a 32-byte blake2b hash of the given data
hash hash_data(std::string_view data);

// Generates a not-proper-Ed25519 Monero signature for the given legacy monero pubkey.
// TODO: start using proper Ed25519 signatures instead.
signature generate_signature(const hash& prefix_hash, const legacy_keypair& keys);

// Verifies the not-proper-Ed25519 Monero signature against the given public key
bool check_signature(const signature& sig, const hash& prefix_hash, const legacy_pubkey& pub);

}  // namespace oxen::crypto
