#pragma once

#include "lokid_key.h"

#include <array>

namespace loki {

constexpr size_t HASH_SIZE = 32;
constexpr size_t EC_SCALAR_SIZE = 32;

using hash = std::array<uint8_t, HASH_SIZE>;
using ec_scalar = std::array<uint8_t, EC_SCALAR_SIZE>;

struct signature {
    ec_scalar c, r;
};

hash hash_data(const std::string& data);

signature generate_signature(const hash& prefix_hash,
                             const lokid_key_pair_t& key_pair);

bool check_signature(const std::string& signature, const hash& hash,
                     const std::string& public_key_t_b32z);
bool check_signature(const signature& sig, const hash& prefix_hash,
                     const public_key_t& pub);

} // namespace loki
