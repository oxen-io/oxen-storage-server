#include "channel_encryption.hpp"

#include <openssl/evp.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/randombytes.h>
#include <oxenmq/hex.h>

#include "utils.hpp"

#include <exception>

#include <iostream>

namespace oxen {

namespace {

// Derive shared secret from our (ephemeral) `seckey` and the other party's
// `pubkey`
std::array<uint8_t, crypto_scalarmult_BYTES>
calculate_shared_secret(const x25519_seckey& seckey,
                        const x25519_pubkey& pubkey) {

    std::array<uint8_t, crypto_scalarmult_BYTES> secret;
    if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0)
        throw std::runtime_error(
            "Shared key derivation failed (crypto_scalarmult)");
    return secret;
}

std::basic_string_view<unsigned char> to_uchar(std::string_view sv) {
    return {reinterpret_cast<const unsigned char*>(sv.data()), sv.size()};
}

inline constexpr std::string_view salt{"LOKI"};

std::array<uint8_t, crypto_scalarmult_BYTES> derive_symmetric_key(
        const x25519_seckey& seckey,
        const x25519_pubkey& pubkey) {

    auto key = calculate_shared_secret(seckey, pubkey);

    auto usalt = to_uchar(salt);

    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, usalt.data(), usalt.size());
    crypto_auth_hmacsha256_update(&state, key.data(), key.size());
    crypto_auth_hmacsha256_final(&state, key.data());

    return key;
}

struct aes256_evp_deleter {
    void operator()(EVP_CIPHER_CTX* ptr) {
        EVP_CIPHER_CTX_free(ptr);
    }
};

using aes256_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, aes256_evp_deleter>;


}

EncryptType parse_enc_type(std::string_view enc_type) {
    if (enc_type == "xchacha20" || enc_type == "xchacha20-poly1305") return EncryptType::xchacha20;
    if (enc_type == "aes-gcm" || enc_type == "gcm") return EncryptType::aes_gcm;
    if (enc_type == "aes-cbc" || enc_type == "cbc") return EncryptType::aes_cbc;
    throw std::runtime_error{"Invalid encryption type " + std::string{enc_type}};
}

std::string ChannelEncryption::encrypt(EncryptType type, std::string_view plaintext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return encrypt_xchacha20(plaintext, pubkey);
        case EncryptType::aes_gcm: return encrypt_gcm(plaintext, pubkey);
        case EncryptType::aes_cbc: return encrypt_cbc(plaintext, pubkey);
    }
    throw std::runtime_error{"Invalid encryption type"};
}

std::string ChannelEncryption::decrypt(EncryptType type, std::string_view ciphertext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return decrypt_xchacha20(ciphertext, pubkey);
        case EncryptType::aes_gcm: return decrypt_gcm(ciphertext, pubkey);
        case EncryptType::aes_cbc: return decrypt_cbc(ciphertext, pubkey);
    }
    throw std::runtime_error{"Invalid decryption type"};
}

static std::string encrypt_openssl(
        const EVP_CIPHER* cipher,
        int taglen,
        std::basic_string_view<unsigned char> plaintext,
        const std::array<uint8_t, crypto_scalarmult_BYTES>& key) {

    // Initialise cipher context
    aes256_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
    auto* ctx = ctx_ptr.get();

    std::string output;
    // Start the output with the iv, then output space plus an extra possible 'blockSize' (according
    // to libssl docs) for the cipher data.
    const int ivLength = EVP_CIPHER_iv_length(cipher);
    output.resize(ivLength + plaintext.size() + EVP_CIPHER_block_size(cipher) + taglen);
    auto* o = reinterpret_cast<unsigned char*>(output.data());
    randombytes_buf(o, ivLength);
    const auto* iv = o;
    o += ivLength;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv) <= 0) {
        throw std::runtime_error("Could not initialise encryption context");
    }

    int len;
    // Encrypt every full blocks
    if (EVP_EncryptUpdate(ctx, o, &len, plaintext.data(), plaintext.size()) <= 0) {
        throw std::runtime_error("Could not encrypt plaintext");
    }
    o += len;

    // Encrypt any remaining partial blocks
    if (EVP_EncryptFinal_ex(ctx, o, &len) <= 0) {
        throw std::runtime_error("Could not finalise encryption");
    }
    o += len;

    // Add the tag, if applicable (e.g. aes-gcm)
    if (taglen > 0 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, taglen, o) <= 0)
        throw std::runtime_error{"Failed to copy encryption tag"};
    o += taglen;

    // Remove excess buffer space
    output.resize(reinterpret_cast<char*>(o) - output.data());

    return output;
}

static std::string decrypt_openssl(
        const EVP_CIPHER* cipher,
        int taglen,
        std::basic_string_view<unsigned char> ciphertext,
        const std::array<uint8_t, crypto_scalarmult_BYTES>& key) {

    // Initialise cipher context
    aes256_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
    auto* ctx = ctx_ptr.get();

    // We prepend the iv on the beginning of the ciphertext; extract it
    auto iv = ciphertext.substr(0, EVP_CIPHER_iv_length(cipher));
    ciphertext.remove_prefix(iv.size());

    // We also append the tag (if applicable) so extract it:
    if (ciphertext.size() < taglen)
        throw std::runtime_error{"Encrypted value is too short"};
    auto tag = ciphertext.substr(ciphertext.size() - taglen);
    ciphertext.remove_suffix(tag.size());

    // libssl docs say we need up to block size of extra buffer space:
    std::string output;
    output.resize(ciphertext.size() + EVP_CIPHER_block_size(cipher));

    // Initialise cipher context
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) <= 0) {
        throw std::runtime_error("Could not initialise decryption context");
    }

    int len;
    auto* o = reinterpret_cast<unsigned char*>(output.data());

    // Decrypt every full blocks
    if (EVP_DecryptUpdate(ctx, o, &len, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error("Could not decrypt block");
    }
    o += len;

    if (!tag.empty() && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, (void*) tag.data()) <= 0)
        throw std::runtime_error{"Could not set decryption tag"};

    // Decrypt any remaining partial blocks
    if (EVP_DecryptFinal_ex(ctx, o, &len) <= 0) {
        throw std::runtime_error("Could not finalise decryption");
    }
    o += len;

    // Remove excess buffer space
    output.resize(reinterpret_cast<char*>(o) - output.data());

    return output;
}

std::string ChannelEncryption::encrypt_cbc(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {
    return encrypt_openssl(
            EVP_aes_256_cbc(), 0,
            to_uchar(plaintext_),
            calculate_shared_secret(private_key_, pubKey));
}

std::string ChannelEncryption::decrypt_cbc(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {
    return decrypt_openssl(
            EVP_aes_256_cbc(), 0,
            to_uchar(ciphertext_),
            calculate_shared_secret(private_key_, pubKey));
}

std::string ChannelEncryption::encrypt_gcm(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {

    return encrypt_openssl(
            EVP_aes_256_gcm(), 16 /* tag length */,
            to_uchar(plaintext_),
            derive_symmetric_key(private_key_, pubKey));
}

std::string ChannelEncryption::decrypt_gcm(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {

    return decrypt_openssl(
            EVP_aes_256_gcm(), 16 /* tag length */,
            to_uchar(ciphertext_),
            derive_symmetric_key(private_key_, pubKey));
}

static std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
xchacha20_shared_key(
        const x25519_pubkey& local_pub,
        const x25519_seckey& local_sec,
        const x25519_pubkey& remote_pub,
        bool local_first) {
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key;
    static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES >= crypto_scalarmult_BYTES);
    if (0 != crypto_scalarmult(key.data(), local_sec.data(), remote_pub.data())) // Use key as tmp storage for aB
        throw std::runtime_error{"Failed to compute shared key for xchacha20"};
    crypto_generichash_state h;
    crypto_generichash_init(&h, nullptr, 0, key.size());
    crypto_generichash_update(&h, key.data(), crypto_scalarmult_BYTES);
    crypto_generichash_update(&h, (local_first ? local_pub : remote_pub).data(), local_pub.size());
    crypto_generichash_update(&h, (local_first ? remote_pub : local_pub).data(), local_pub.size());
    crypto_generichash_final(&h, key.data(), key.size());
    return key;
}

std::string ChannelEncryption::encrypt_xchacha20(std::string_view plaintext_, const x25519_pubkey& pubKey) const {
    auto plaintext = to_uchar(plaintext_);

    std::string ciphertext;
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + plaintext.size()
            + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    // Generate random nonce, and stash it at the beginning of ciphertext:
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    auto* c = reinterpret_cast<unsigned char*>(ciphertext.data())
        + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            c, &clen,
            plaintext.data(), plaintext.size(),
            nullptr, 0, // additional data
            nullptr, // nsec (always unused)
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            key.data());
    assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen <= ciphertext.size());
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen);
    return ciphertext;
}

std::string ChannelEncryption::decrypt_xchacha20(std::string_view ciphertext_, const x25519_pubkey& pubKey) const {
    auto ciphertext = to_uchar(ciphertext_);

    // Extract nonce from the beginning of the ciphertext:
    auto nonce = ciphertext.substr(0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext.remove_prefix(nonce.size());
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error{"Invalid ciphertext: too short"};

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    std::string plaintext;
    plaintext.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    auto* m = reinterpret_cast<unsigned char*>(plaintext.data());
    unsigned long long mlen;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
            m, &mlen,
            nullptr, // nsec (always unused)
            ciphertext.data(), ciphertext.size(),
            nullptr, 0, // additional data
            nonce.data(),
            key.data()))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    assert(mlen <= plaintext.size());
    plaintext.resize(mlen);
    return plaintext;
}

}
