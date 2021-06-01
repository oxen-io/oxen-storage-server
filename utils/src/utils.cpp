#include "utils.hpp"

#include <cstring>

#ifndef _WIN32
extern "C" {
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
}
#endif

namespace util {

std::mt19937_64& rng() {
    static thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n) {
    const uint64_t secure_max =
        mersenne_twister.max() - mersenne_twister.max() % n;
    uint64_t x;
    do
        x = mersenne_twister();
    while (x >= secure_max);
    return x / (secure_max / n);
}

int get_fd_limit() {

#ifdef _WIN32
    return -1;
#endif

    return sysconf(_SC_OPEN_MAX);
}

std::optional<std::filesystem::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifndef WIN32
    char* home = getenv("HOME");
    if (!home || !strlen(home))
        if (const auto* pwd = getpwuid(getuid()))
            home = pwd->pw_dir;

    if (home && strlen(home))
        return std::filesystem::u8path(home);
#endif

    return std::nullopt;
}

} // namespace util
