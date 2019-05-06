#pragma once

#include "lokid_key.h"

#include <array>

namespace loki {

using hash = std::array<uint8_t, 32>;
// using public_key_t = std::array<uint8_t, 32>;
// using secret_key_t = std::array<uint8_t, 32>;
using ec_scalar = std::array<uint8_t, 32>;

struct signature {
    ec_scalar c, r;
};

hash hash_data(const std::string& data);

void generate_signature(const hash& prefix_hash, const lokid_key_pair_t& key_pair, signature& sig);

bool check_signature(const std::string& signature, const hash& hash,
                     const std::string& public_key_t_b32z);
bool check_signature(const signature& sig, const hash& prefix_hash,
                     const public_key_t& pub);

} // namespace loki
