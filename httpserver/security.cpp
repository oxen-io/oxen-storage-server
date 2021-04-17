#include "security.h"
#include "oxend_key.h"
#include "signature.h"

#include <oxenmq/base64.h>

#include <filesystem>
#include <fstream>

namespace oxen {
Security::Security(legacy_keypair key_pair,
                   std::filesystem::path base_path)
    : key_pair_{std::move(key_pair)}, base_path_{std::move(base_path)} {}

void Security::generate_cert_signature() {
    std::ifstream file{base_path_ / "cert.pem"};
    if (!file.is_open()) {
        throw std::runtime_error("Could not find cert.pem");
    }
    std::string cert_pem((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    const auto hash = hash_data(cert_pem);
    const auto sig = generate_signature(hash, key_pair_);
    std::string_view raw_sig{reinterpret_cast<const char*>(&sig), sizeof(sig)};
    cert_signature_ = oxenmq::to_base64(raw_sig);
}

} // namespace oxen
