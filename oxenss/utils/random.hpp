#include <random>
#include <cstdint>

namespace oxenss::util {

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n); (copied from lokid)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister, uint64_t n);

}  // namespace oxenss::util
