#include "keys.h"

#include <oxenss/logging/oxen_logger.h>

#include <cstring>
#include <type_traits>

#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>

namespace oxen::crypto {

static auto logcat = oxen::log::Cat("crypto");

namespace detail {
    void load_from_hex(void* buffer, size_t length, std::string_view hex) {
        if (!oxenc::is_hex(hex))
            throw std::runtime_error{"Hex key data is invalid: data is not hex"};
        if (hex.size() != 2 * length)
            throw std::runtime_error{
                    "Hex key data is invalid: expected " + std::to_string(length) +
                    " hex digits, received " + std::to_string(hex.size())};
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(buffer));
    }

    void load_from_bytes(void* buffer, size_t length, std::string_view bytes) {
        if (bytes.size() != length)
            throw std::runtime_error{
                    "Key data is invalid: expected " + std::to_string(length) +
                    " bytes, received " + std::to_string(bytes.size())};
        std::memmove(buffer, bytes.data(), length);
    }

    std::string to_hex(const unsigned char* buffer, size_t length) {
        return oxenc::to_hex(buffer, buffer + length);
    }

}  // namespace detail

std::string ed25519_pubkey::snode_address() const {
    auto addr = oxenc::to_base32z(begin(), end());
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

template <typename T>
static T parse_pubkey(std::string_view pubkey_in) {
    T pk{};
    static_assert(pk.size() == 32);
    if (pubkey_in.size() == 32)
        detail::load_from_bytes(pk.data(), 32, pubkey_in);
    else if (pubkey_in.size() == 64 && oxenc::is_hex(pubkey_in))
        oxenc::from_hex(pubkey_in.begin(), pubkey_in.end(), pk.begin());
    else if (
            (pubkey_in.size() == 43 || (pubkey_in.size() == 44 && pubkey_in.back() == '=')) &&
            oxenc::is_base64(pubkey_in))
        oxenc::from_base64(pubkey_in.begin(), pubkey_in.end(), pk.begin());
    else if (pubkey_in.size() == 52 && oxenc::is_base32z(pubkey_in))
        oxenc::from_base32z(pubkey_in.begin(), pubkey_in.end(), pk.begin());
    else {
        log::warning(logcat, "Invalid public key: not valid bytes, hex, b64, or b32z encoded");
        log::debug(
                logcat,
                "Received public key encoded value of size {}: {}",
                pubkey_in.size(),
                pubkey_in);
    }
    return pk;
}

legacy_pubkey parse_legacy_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<legacy_pubkey>(pubkey_in);
}
ed25519_pubkey parse_ed25519_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<ed25519_pubkey>(pubkey_in);
}
x25519_pubkey parse_x25519_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<x25519_pubkey>(pubkey_in);
}

std::array<unsigned char, 32> subkey_verify_key(std::string_view pubkey, std::string_view subkey) {

    if (pubkey.size() != 32 || subkey.size() != 32)
        throw std::invalid_argument{"Invalid pubkey/subkey: both must be 32 bytes"};

    return subkey_verify_key(
            reinterpret_cast<const unsigned char*>(pubkey.data()),
            reinterpret_cast<const unsigned char*>(subkey.data()));
}

std::array<unsigned char, 32> subkey_verify_key(
        const unsigned char* pubkey, const unsigned char* subkey) {

    std::array<unsigned char, 32> subkey_pub;
    // Need to compute: (c + H(c || A, key="OxenSSSubkey")) A and use that instead of A for
    // verification:

    // H(c || A, key="OxenSSSubkey"):
    crypto_generichash_state h_state;
    crypto_generichash_init(
            &h_state,
            reinterpret_cast<const unsigned char*>(SUBKEY_HASH_KEY.data()),
            SUBKEY_HASH_KEY.size(),
            32);
    crypto_generichash_update(&h_state, subkey, 32);  // c
    crypto_generichash_update(&h_state, pubkey, 32);  // A
    crypto_generichash_final(&h_state, subkey_pub.data(), 32);

    // c + H(...):
    crypto_core_ed25519_scalar_add(subkey_pub.data(), subkey, subkey_pub.data());

    // (c + H(...)) A:
    if (0 != crypto_scalarmult_ed25519_noclamp(subkey_pub.data(), subkey_pub.data(), pubkey))
        throw std::invalid_argument{"Invalid pubkey/subkey combination"};

    return subkey_pub;
}

}  // namespace oxen::crypto
