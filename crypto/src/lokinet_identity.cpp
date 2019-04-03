#include "lokinet_identity.hpp"
extern "C" {
#include "sodium/private/ed25519_ref10.h"
}

#include <boost/filesystem.hpp>

#include <exception>
#include <fstream>
#include <iterator>

namespace fs = boost::filesystem;

constexpr size_t keyLength = 32;

std::vector<uint8_t> parseLokinetIdentityPrivate(const std::string& path) {
    fs::path p(path);

    if (p.empty()) {
#ifdef _WIN32
        const fs::path homedir = fs::pathpath(getenv("APPDATA"));
#else
        const fs::path homedir = fs::path(getenv("HOME"));
#endif
        const fs::path basepath = homedir / fs::path(".lokinet");
        p = basepath / "identity.private";
    }

    if (!fs::exists(p)) {
        throw std::runtime_error(
            "Lokinet identity.private file could not be found");
    }
    std::ifstream input(p.c_str(), std::ios::binary);
    const std::vector<uint8_t> privateKey(std::istreambuf_iterator<char>(input), {});

    return privateKey;
}

std::vector<uint8_t> parseLokinetIdentityPublic(const std::string& path) {
    fs::path p(path);

    if (p.empty()) {
#ifdef _WIN32
        const fs::path homedir = fs::pathpath(getenv("APPDATA"));
#else
        const fs::path homedir = fs::path(getenv("HOME"));
#endif
        const fs::path basepath = homedir / fs::path(".loki");
        p = basepath / "identity.private";
    }

    if (!fs::exists(p)) {
        throw std::runtime_error(
            "Lokinet identity.private file could not be found");
    }
    std::ifstream input(p.c_str(), std::ios::binary);
    const std::vector<uint8_t> privateKey(std::istreambuf_iterator<char>(input), {});
    ge25519_p3 A;
    ge25519_scalarmult_base(&A, privateKey.data());
    std::vector<uint8_t> publicKey(keyLength);
    ge25519_p3_tobytes(publicKey.data(), &A);

    return publicKey;
}
