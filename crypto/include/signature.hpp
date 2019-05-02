#pragma once

#include <sodium/crypto_generichash.h>

#include <array>

namespace signature {

using hash = std::array<uint8_t, crypto_generichash_BYTES>;
using public_key = std::array<uint8_t, 32>;
using secret_key = std::array<uint8_t, 32>;
using ec_scalar = std::array<uint8_t, 32>;

struct signature {
    ec_scalar c, r;
};

hash hash_data(const std::string& data);

void generate_signature(const hash& prefix_hash, const public_key& pub,
                        const secret_key& sec, signature& sig);

bool check_signature(const std::string& signature, const hash& hash,
                     const std::string& public_key_b32z);
bool check_signature(const signature& sig, const hash& prefix_hash,
                     const public_key& pub);

} // namespace signature
