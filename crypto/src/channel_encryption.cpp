#include "channel_encryption.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <oxenmq/hex.h>

#include "utils.hpp"

#include <exception>

#include <iostream>

namespace oxen {

namespace {

// Derive shared secret from our (ephemeral) `seckey` and the other party's
// `pubkey`
std::vector<uint8_t>
calculate_shared_secret(const x25519_seckey& seckey,
                        const x25519_pubkey& pubkey) {

    std::vector<uint8_t> secret(crypto_scalarmult_BYTES);
    static_assert(sizeof(pubkey) == crypto_scalarmult_BYTES);

    if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0) {
        throw std::runtime_error(
            "Shared key derivation failed (crypto_scalarmult)");
    }
    return secret;
}

inline constexpr std::string_view salt{"LOKI"};

std::vector<uint8_t>
derive_symmetric_key(const x25519_seckey seckey,
                     const x25519_pubkey pubkey) {

    auto key = calculate_shared_secret(seckey, pubkey);

    const auto* usalt = reinterpret_cast<const unsigned char*>(salt.data());

    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, usalt, salt.size());
    crypto_auth_hmacsha256_update(&state, key.data(), key.size());
    crypto_auth_hmacsha256_final(&state, key.data());

    return key;
}

struct aes256_evp_deleter {
    void operator()(EVP_CIPHER_CTX* ptr) {
        EVP_CIPHER_CTX_free(ptr);
    }
};

using aes256cbc_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, aes256_evp_deleter>;


}

std::string ChannelEncryption::encrypt_cbc(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {

    std::basic_string_view<unsigned char> plaintext{
        reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size()};

    const auto sharedKey = calculate_shared_secret(private_key_, pubKey);

    // Initialise cipher context
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    aes256cbc_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
    auto* ctx = ctx_ptr.get();

    std::string output;
    // Start the output with the iv, then output space plus an extra possible 'blockSize' (according
    // to libssl docs) for the cipher data.
    const int ivLength = EVP_CIPHER_iv_length(cipher);
    output.resize(ivLength + plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    auto* o = reinterpret_cast<unsigned char*>(output.data());
    randombytes_buf(o, ivLength);
    const auto* iv = o;
    o += ivLength;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, sharedKey.data(), iv) <= 0) {
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

    // Remove excess buffer space
    output.resize(reinterpret_cast<char*>(o) - output.data());

    EVP_CIPHER_CTX_free(ctx);

    return output;
}

std::string ChannelEncryption::encrypt_gcm(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {

    std::basic_string_view<unsigned char> plaintext{
        reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size()};

    const auto derived_key = derive_symmetric_key(private_key_, pubKey);

    // Output will be nonce(12B) || ciphertext || tag(16B)
    std::string output;
    output.resize(
            crypto_aead_aes256gcm_NPUBBYTES + plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    auto* nonce = reinterpret_cast<unsigned char*>(output.data());
    randombytes_buf(nonce, crypto_aead_aes256gcm_NPUBBYTES);

    auto* ciphertext = nonce + crypto_aead_aes256gcm_NPUBBYTES;
    unsigned long long ciphertext_len;

    crypto_aead_aes256gcm_encrypt(
            ciphertext, &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0, // ad, adlen
            nullptr, // nsec (not used by aes256gcm)
            nonce,
            derived_key.data());

    output.resize(crypto_aead_aes256gcm_NPUBBYTES + ciphertext_len);
    return output;
}

std::string ChannelEncryption::decrypt_gcm(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {

    const auto derived_key = derive_symmetric_key(private_key_, pubKey);

    std::basic_string_view<unsigned char> ciphertext{
        reinterpret_cast<const unsigned char*>(ciphertext_.data()), ciphertext_.size()};

    // Remove the nonce that we stick on the beginning:
    auto nonce = ciphertext.substr(0, crypto_aead_aes256gcm_NPUBBYTES);
    ciphertext.remove_prefix(nonce.size());

    // Plaintext output will be ABYTES shorter than the ciphertext
    std::string output;
    output.resize(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);

    auto outPtr = reinterpret_cast<unsigned char*>(&output[0]);

    unsigned long long decrypted_len;
    if (int result = crypto_aead_aes256gcm_decrypt(
                reinterpret_cast<unsigned char*>(output.data()), &decrypted_len,
                nullptr, // nsec, always null for aes256gcm
                ciphertext.data(), ciphertext.size(),
                nullptr, 0, // ad, adlen
                nonce.data(),
                derived_key.data());
            result != 0) {
        throw std::runtime_error("Could not decrypt (AES-GCM)");
    }

    assert(output.size() == decrypted_len);

    return output;
}

std::string ChannelEncryption::decrypt_cbc(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {

    std::basic_string_view<unsigned char> ciphertext{
        reinterpret_cast<const unsigned char*>(ciphertext_.data()), ciphertext_.size()};

    const auto sharedKey = calculate_shared_secret(private_key_, pubKey);

    // Initialise cipher context
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    aes256cbc_ctx_ptr ctx_ptr{EVP_CIPHER_CTX_new()};
    auto* ctx = ctx_ptr.get();

    // We prepend the iv on the beginning of the ciphertext; extract it
    auto iv = ciphertext.substr(0, EVP_CIPHER_iv_length(cipher));
    ciphertext.remove_prefix(iv.size());

    // libssl docs say we need up to block size of extra buffer space:
    std::string output;
    output.resize(ciphertext.size() + EVP_CIPHER_CTX_block_size(ctx));

    // Initialise cipher context
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, sharedKey.data(), iv.data()) <= 0) {
        throw std::runtime_error("Could not initialise decryption context");
    }

    int len;
    auto* o = reinterpret_cast<unsigned char*>(output.data());

    // Decrypt every full blocks
    if (EVP_DecryptUpdate(ctx, o, &len, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error("Could not decrypt block");
    }
    o += len;

    // Decrypt any remaining partial blocks
    if (EVP_DecryptFinal_ex(ctx, o, &len) <= 0) {
        throw std::runtime_error("Could not finalise decryption");
    }
    o += len;

    // Remove excess buffer space
    output.resize(reinterpret_cast<char*>(o) - output.data());

    return output;
}

}
