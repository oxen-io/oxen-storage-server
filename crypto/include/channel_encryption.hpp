#pragma once

#include <string>
#include <string_view>

#include "oxend_key.h"

namespace oxen {

enum class EncryptType {
    aes_cbc,
    aes_gcm,
    xchacha20,
};

// Takes the encryption type as a string, returns the EncryptType value (or throws if invalid).
// Supported values: aes-gcm, aes-cbc, xchacha20.  gcm and cbc are accepted as aliases for the aes-
// version.
EncryptType parse_enc_type(std::string_view enc_type);

inline constexpr std::string_view to_string(EncryptType type) {
    switch (type) {
        case EncryptType::xchacha20: return "xchacha20"sv;
        case EncryptType::aes_gcm: return "aes-gcm"sv;
        case EncryptType::aes_cbc: return "aes-cbc"sv;
    }
    return ""sv;
}

// Encryption/decription class for encryption/decrypting outgoing/incoming messages.
class ChannelEncryption {
  public:
    ChannelEncryption(x25519_seckey private_key, x25519_pubkey public_key)
        : private_key_{std::move(private_key)}, public_key_{std::move(public_key)} {}

    std::string encrypt(EncryptType type, std::string_view plaintext, const x25519_pubkey& pubkey) const;
    std::string decrypt(EncryptType type, std::string_view ciphertext, const x25519_pubkey& pubkey) const;

    // AES-CBC encryption.
    std::string encrypt_cbc(std::string_view plainText, const x25519_pubkey& pubKey) const;
    std::string decrypt_cbc(std::string_view cipherText, const x25519_pubkey& pubKey) const;

    // AES-GCM encryption.
    std::string encrypt_gcm(std::string_view plainText, const x25519_pubkey& pubKey) const;
    std::string decrypt_gcm(std::string_view cipherText, const x25519_pubkey& pubKey) const;

    // xchacha20-poly1305 encryption; for a message sent from Alice to Bob we use a shared key of a
    // Blake2B 32-byte (i.e.  crypto_aead_xchacha20poly1305_ietf_KEYBYTES) hash of H(aB || A || B),
    // which Bob can compute when receiving as H(bA || A || B).  The returned value always has the
    // crypto_aead_xchacha20poly1305_ietf_NPUBBYTES nonce prepended to the beginning.
    std::string encrypt_xchacha20(std::string_view plaintext, const x25519_pubkey& pubKey) const;
    std::string decrypt_xchacha20(std::string_view ciphertext, const x25519_pubkey& pubKey) const;

  private:
    const x25519_seckey private_key_;
    const x25519_pubkey public_key_;
};

}
