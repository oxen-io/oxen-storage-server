#include "channel_encryption.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <lokimq/hex.h>

#include "utils.hpp"

#include <exception>
#include <string>

#include <iostream>

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> temp;
    if (!lokimq::is_hex(hex)) throw std::runtime_error{"input is not hex"};
    temp.reserve(hex.size() / 2);
    lokimq::from_hex(hex.begin(), hex.end(), std::back_inserter(temp));
    return temp;
}

template <typename T>
ChannelEncryption<T>::ChannelEncryption(const std::vector<uint8_t>& private_key)
    : private_key_(private_key) {}

// Derive shared secret from our (ephemeral) `seckey` and the other party's
// `pubkey`
static std::vector<uint8_t>
calculate_shared_secret(const std::vector<uint8_t>& seckey,
                        const std::vector<uint8_t>& pubkey) {

    std::vector<uint8_t> secret(crypto_scalarmult_BYTES);
    if (pubkey.size() != crypto_scalarmult_curve25519_BYTES) {
        throw std::runtime_error("Bad pubKey size");
    }

    if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0) {
        throw std::runtime_error(
            "Shared key derivation failed (crypto_scalarmult)");
    }
    return secret;
}

static std::vector<uint8_t>
derive_symmetric_key(const std::vector<uint8_t>& seckey,
                     const std::vector<uint8_t>& pubkey) {

    const std::vector<uint8_t> sharedKey =
        calculate_shared_secret(seckey, pubkey);

    std::vector<uint8_t> derived_key(32);

    const std::string salt_str = "LOKI";
    const auto salt = reinterpret_cast<const unsigned char*>(salt_str.data());

    crypto_auth_hmacsha256_state state;

    crypto_auth_hmacsha256_init(&state, salt, salt_str.size());
    crypto_auth_hmacsha256_update(&state, sharedKey.data(), sharedKey.size());
    crypto_auth_hmacsha256_final(&state, derived_key.data());

    return derived_key;
}

template <typename T>
T ChannelEncryption<T>::encrypt_cbc(const T& plaintext,
                                    const std::string& pubKey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubKey);
    const std::vector<uint8_t> sharedKey =
        calculate_shared_secret(this->private_key_, pubKeyBytes);

    // Initialise cipher
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const int ivLength = EVP_CIPHER_iv_length(cipher);

    // Generate IV
    unsigned char iv[ivLength];
    if (RAND_bytes(iv, ivLength) != 1) {
        throw std::runtime_error("Could not generate IV");
    }

    // Initialise cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, sharedKey.data(), iv) <= 0) {
        throw std::runtime_error("Could not initialise encryption context");
    }

    int len;
    size_t ciphertext_len = 0;
    auto p = reinterpret_cast<const unsigned char*>(plaintext.data());
    const size_t plaintext_len = plaintext.size();

    // Add some padding of 'blockSize' as upper limit
    const int blockSize = EVP_CIPHER_CTX_block_size(ctx);
    T output;
    output.resize(plaintext_len + blockSize);
    auto o = reinterpret_cast<unsigned char*>(&output[0]);

    // Encrypt every full blocks
    if (EVP_EncryptUpdate(ctx, o, &len, p, plaintext_len) <= 0) {
        throw std::runtime_error("Could not encrypt plaintext");
    }
    ciphertext_len += len;

    // Encrypt any remaining partial blocks
    if (EVP_EncryptFinal_ex(ctx, o + len, &len) <= 0) {
        throw std::runtime_error("Could not finalise encryption");
    }
    ciphertext_len += len;

    // Remove excess padding
    output.resize(ciphertext_len);

    // Insert iv at the start
    output.insert(output.begin(), iv, iv + ivLength);

    EVP_CIPHER_CTX_free(ctx);

    return output;
}

template <typename T>
T ChannelEncryption<T>::encrypt_gcm(const T& plaintext,
                                    const std::string& pubKey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubKey);
    const std::vector<uint8_t> derived_key =
        derive_symmetric_key(this->private_key_, pubKeyBytes);

    T ciphertext;
    // Ciphertext should always be the length of plaintext plus tag
    ciphertext.resize(plaintext.size() + 16);

    auto ciphertext_ptr = reinterpret_cast<unsigned char*>(&ciphertext[0]);

    unsigned long long ciphertext_len;

    const auto plaintext_ptr =
        reinterpret_cast<const unsigned char*>(&plaintext[0]);

    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    crypto_aead_aes256gcm_encrypt(ciphertext_ptr, &ciphertext_len,
                                  plaintext_ptr, plaintext.size(), NULL, 0,
                                  NULL, nonce, derived_key.data());

    ciphertext.resize(ciphertext_len);

    ciphertext.insert(ciphertext.begin(), std::begin(nonce), std::end(nonce));

    // nonce (12 bytes) || ciphertext || tag (16 bytes)
    return ciphertext;
}

template <typename T>
T ChannelEncryption<T>::decrypt_gcm(const T& iv_ciphertext_tag,
                                    const std::string& pubKey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubKey);
    const std::vector<uint8_t> derived_key =
        derive_symmetric_key(this->private_key_, pubKeyBytes);

    T output;

    // Plaintext should be (16 + 12) bytes shorter
    output.resize(iv_ciphertext_tag.size() - 28);

    auto outPtr = reinterpret_cast<unsigned char*>(&output[0]);

    unsigned long long decrypted_len;

    constexpr auto NONCE_SIZE = 12;
    const auto ciphertext = reinterpret_cast<const unsigned char*>(
        &iv_ciphertext_tag[0] + NONCE_SIZE);

    const auto nonce =
        reinterpret_cast<const unsigned char*>(&iv_ciphertext_tag[0]);

    unsigned long long clen = iv_ciphertext_tag.size() - NONCE_SIZE;

    if (crypto_aead_aes256gcm_decrypt(
            outPtr, &decrypted_len, NULL /* must be null */, ciphertext, clen,
            NULL, 0, nonce, derived_key.data()) != 0) {
        throw std::runtime_error("Could not decrypt (AES-GCM)");
    }

    assert(output.size() == decrypted_len);

    return output;
}

template <typename T>
T ChannelEncryption<T>::decrypt_cbc(const T& ciphertextAndIV,
                                    const std::string& pubKey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubKey);
    const std::vector<uint8_t> sharedKey =
        calculate_shared_secret(this->private_key_, pubKeyBytes);

    // Initialise cipher
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    const int ivLength = EVP_CIPHER_iv_length(cipher);

    auto inPtr = reinterpret_cast<const unsigned char*>(&ciphertextAndIV[0]);

    // Initialise cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, sharedKey.data(), inPtr) <= 0) {
        throw std::runtime_error("Could not initialise decryption context");
    }

    int len;
    size_t plaintextLength = 0;
    const size_t ciphertextLength = ciphertextAndIV.size() - ivLength;

    // Add some padding of 'blockSize' as upper limit
    const int blockSize = EVP_CIPHER_CTX_block_size(ctx);
    T output;
    output.resize(ciphertextLength + blockSize);

    auto outPtr = reinterpret_cast<unsigned char*>(&output[0]);

    // Decrypt every full blocks
    if (EVP_DecryptUpdate(ctx, outPtr, &len, inPtr + ivLength,
                          ciphertextLength) <= 0) {
        throw std::runtime_error("Could not decrypt block");
    }
    plaintextLength += len;

    // Decrypt any remaining partial blocks
    if (EVP_DecryptFinal_ex(ctx, outPtr + len, &len) <= 0) {
        throw std::runtime_error("Could not finalise decryption");
    }
    plaintextLength += len;

    // Remove excess bytes
    output.resize(plaintextLength);

    // Don't we need to call free even when we throw??
    EVP_CIPHER_CTX_free(ctx);
    return output;
}

// explicit template specialization
template class ChannelEncryption<std::string>;

template class ChannelEncryption<std::vector<uint8_t>>;
