#include "random.hpp"

namespace oxenss::util {

std::mt19937_64& rng() {
    static thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister, uint64_t n) {
    const uint64_t secure_max = mersenne_twister.max() - mersenne_twister.max() % n;
    uint64_t x;
    do
        x = mersenne_twister();
    while (x >= secure_max);
    return x / (secure_max / n);
}

}  // namespace oxenss::util
