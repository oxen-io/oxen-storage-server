#include "oxend_key.h"

#include <cstring>
#include <type_traits>

#include <sodium.h>
#include <oxenmq/base32z.h>
#include <oxenmq/hex.h>

namespace oxen {

namespace detail {

void load_from_hex(void* buffer, size_t length, std::string_view hex) {
    if (!oxenmq::is_hex(hex))
        throw std::runtime_error{"Hex key data is invalid: data is not hex"};
    if (hex.size() != 2*length)
        throw std::runtime_error{
            "Hex key data is invalid: expected " + std::to_string(length) +
                " hex digits, received " + std::to_string(hex.size())};
    oxenmq::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(buffer));
}

void load_from_bytes(void* buffer, size_t length, std::string_view bytes) {
    if (bytes.size() != length)
        throw std::runtime_error{
            "Key data is invalid: expected " + std::to_string(length) +
                " bytes, received " + std::to_string(bytes.size())};
    std::memmove(buffer, bytes.data(), length);
}

std::string to_hex(const unsigned char* buffer, size_t length) {
    return oxenmq::to_hex(buffer, buffer + length);
}

}

std::string ed25519_pubkey::snode_address() const {
    auto addr = oxenmq::to_base32z(begin(), end());
    addr += ".snode";
    return addr;
}

legacy_pubkey legacy_seckey::pubkey() const {
    legacy_pubkey pk;
    crypto_scalarmult_ed25519_base_noclamp(pk.data(), data());
    return pk;
};
ed25519_pubkey ed25519_seckey::pubkey() const {
    ed25519_pubkey pk;
    crypto_sign_ed25519_sk_to_pk(pk.data(), data());
    return pk;
};
x25519_pubkey x25519_seckey::pubkey() const {
    x25519_pubkey pk;
    crypto_scalarmult_curve25519_base(pk.data(), data());
    return pk;
};

} // namespace oxen
