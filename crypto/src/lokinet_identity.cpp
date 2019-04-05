#include "lokinet_identity.hpp"

#include <boost/filesystem.hpp>

#include <exception>
#include <fstream>
#include <iterator>

namespace fs = boost::filesystem;

constexpr size_t PRIVATE_KEY_OFFSET = 3;
constexpr size_t KEY_LENGTH = 32;
constexpr size_t PUBLIC_KEY_OFFSET = PRIVATE_KEY_OFFSET + KEY_LENGTH;

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
    const std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(input), {});
    const std::vector<uint8_t> privateKey(bytes.begin() + PRIVATE_KEY_OFFSET,
                                          bytes.begin() + PRIVATE_KEY_OFFSET +
                                              KEY_LENGTH);

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
        const fs::path basepath = homedir / fs::path(".lokinet");
        p = basepath / "identity.private";
    }

    if (!fs::exists(p)) {
        throw std::runtime_error(
            "Lokinet identity.private file could not be found");
    }
    std::ifstream input(p.c_str(), std::ios::binary);
    const std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(input), {});
    const std::vector<uint8_t> publicKey(bytes.begin() + PUBLIC_KEY_OFFSET,
                                         bytes.begin() + PUBLIC_KEY_OFFSET +
                                             KEY_LENGTH);

    return publicKey;
}
