#include "security.h"
#include "lokid_key.h"
#include "signature.h"

#include <fstream>

#include <boost/beast/core/detail/base64.hpp>

namespace loki {
Security::Security(const lokid_key_pair_t& key_pair) : key_pair_(key_pair) {}

std::string Security::base64_sign(const std::string& body) {
    const auto hash = hash_data(body);
    const auto sig = generate_signature(hash, key_pair_);
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());
    return boost::beast::detail::base64_encode(raw_sig);
}

void Security::generate_cert_signature() {
    std::ifstream file("./cert.pem");
    std::string cert_pem((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    const auto hash = hash_data(cert_pem);
    const auto sig = generate_signature(hash, key_pair_);
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());

    cert_signature_ = boost::beast::detail::base64_encode(raw_sig);
}

std::string Security::get_cert_signature() const { return cert_signature_; }
} // namespace loki