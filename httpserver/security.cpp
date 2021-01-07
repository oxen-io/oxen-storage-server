#include "security.h"
#include "oxend_key.h"
#include "signature.h"

#include <lokimq/base64.h>

#include <filesystem>
#include <fstream>

namespace oxen {
Security::Security(const oxend_key_pair_t& key_pair,
                   const std::filesystem::path& base_path)
    : key_pair_(key_pair), base_path_(base_path) {}

std::string Security::base64_sign(const std::string& body) {
    const auto hash = hash_data(body);
    const auto sig = generate_signature(hash, key_pair_);
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());
    return lokimq::to_base64(raw_sig);
}

void Security::generate_cert_signature() {
    std::ifstream file((base_path_ / "cert.pem").string());
    if (!file.is_open()) {
        throw std::runtime_error("Could not find cert.pem");
    }
    std::string cert_pem((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    const auto hash = hash_data(cert_pem);
    const auto sig = generate_signature(hash, key_pair_);
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());

    cert_signature_ = lokimq::to_base64(raw_sig);
}

std::string Security::get_cert_signature() const { return cert_signature_; }
} // namespace oxen
