#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <random>

namespace util {

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n); (copied from lokid)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n);

/// Return the open file limit (-1 on failure)
int get_fd_limit();

std::optional<std::filesystem::path> get_home_dir();

} // namespace util
