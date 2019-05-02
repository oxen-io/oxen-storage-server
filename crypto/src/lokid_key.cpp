#include "lokid_key.h"
extern "C" {
#include "sodium/private/ed25519_ref10.h"
}

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <exception>
#include <fstream>
#include <iterator>

namespace fs = boost::filesystem;

constexpr size_t KEY_LENGTH = 32;

std::vector<uint8_t> parseLokidKey(const std::string& path) {
    fs::path p(path);

    if (p.empty()) {
#ifdef _WIN32
        const fs::path homedir = fs::pathpath(getenv("APPDATA"));
#else
        const fs::path homedir = fs::path(getenv("HOME"));
#endif
        const fs::path basepath = homedir / fs::path(".loki");
        p = basepath / "key";
    }

    if (!fs::exists(p)) {
        throw std::runtime_error("Lokid key file could not be found");
    }
    std::ifstream input(p.c_str(), std::ios::binary);

    if (!input.is_open()) {
        throw std::runtime_error("Could not open the key file");
    }

    const std::vector<uint8_t> private_key(
        std::istreambuf_iterator<char>(input), {});

    if (private_key.size() != KEY_LENGTH) {
        auto err_msg = boost::str(
            boost::format("Bad private key length: %1% (expected: %2%)") %
            private_key.size() % KEY_LENGTH);
        throw std::runtime_error(err_msg);
    }

    return private_key;
}

std::vector<uint8_t> calcPublicKey(const std::vector<uint8_t>& private_key) {
    ge25519_p3 A;
    ge25519_scalarmult_base(&A, private_key.data());
    std::vector<uint8_t> publicKey(KEY_LENGTH);
    ge25519_p3_tobytes(publicKey.data(), &A);

    return publicKey;
}
