#pragma once

#include <algorithm>
#include <array>
#include <random>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace util {

bool validateTTL(uint64_t ttlInt);
// Convert ttl string into uint64_t, return bool for success/fail
bool parseTTL(const std::string& ttlString, uint64_t& ttl);

bool validateTimestamp(uint64_t timestamp, uint64_t ttl);
// Convert timestamp string into uint64_t, return bool for success/fail
bool parseTimestamp(const std::string& timestampString, const uint64_t ttl,
                    uint64_t& timestamp);

// Get current time in milliseconds
uint64_t get_time_ms();

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n) using `rng()`
uint64_t uniform_distribution_portable(uint64_t n);

/// Returns a random number from [0, n); (copied from lokid)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n);

/// Return the open file limit (-1 on failure)
int get_fd_limit();

} // namespace util
