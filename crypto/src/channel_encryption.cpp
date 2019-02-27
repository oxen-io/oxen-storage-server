#include "channel_encryption.hpp"
#include "lokinet_identity.hpp"

#include <boost/algorithm/hex.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sodium.h>

#include <exception>
#include <string>

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> temp;
    boost::algorithm::unhex(hex, std::back_inserter(temp));
    return temp;
}

template <typename T>
ChannelEncryption<T>::ChannelEncryption(
    const std::string& identityPrivatePath) {
    // Lokinet identity uses ed25519
    const std::vector<uint8_t> privateEd25519Key =
        parseLokinetIdentityPrivate(identityPrivatePath);
    this->privateKey.resize(crypto_scalarmult_curve25519_BYTES);

    // Convert to curve25519
    if (crypto_sign_ed25519_sk_to_curve25519(this->privateKey.data(),
                                             privateEd25519Key.data()) != 0) {
        throw std::runtime_error(
            "Could not convert lokinet private key from ed25519 to curve25519");
    }
}

template <typename T>
std::vector<uint8_t> ChannelEncryption<T>::calculateSharedSecret(
    const std::vector<uint8_t>& pubkey) const {
    std::vector<uint8_t> sharedSecret(crypto_scalarmult_BYTES);
    if (pubkey.size() != crypto_scalarmult_curve25519_BYTES) {
        throw std::runtime_error("Bad pubkey size");
    }
    if (crypto_scalarmult(sharedSecret.data(), this->privateKey.data(),
                          pubkey.data()) != 0) {
        throw std::runtime_error(
            "Shared key derivation failed (crypto_scalarmult)");
    }
    return sharedSecret;
}

template <typename T>
T ChannelEncryption<T>::encrypt(const T& plaintext,
                                const std::string& pubkey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubkey);
    const std::vector<uint8_t> sharedKey = calculateSharedSecret(pubKeyBytes);

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
    //    const T ret(output.begin(), output.end());
    return output;
}

template <typename T>
T ChannelEncryption<T>::decrypt(const T& ciphertextAndIV,
                                const std::string& pubkey) const {
    const std::vector<uint8_t> pubKeyBytes = hexToBytes(pubkey);
    const std::vector<uint8_t> sharedKey = calculateSharedSecret(pubKeyBytes);

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
        throw std::runtime_error("Could not initialise decryption context");
    }
    plaintextLength += len;

    // Decrypt any remaining partial blocks
    if (EVP_DecryptFinal_ex(ctx, outPtr + len, &len) <= 0) {
        throw std::runtime_error("Could not finalise decryption");
    }
    plaintextLength += len;

    // Remove excess bytes
    output.resize(plaintextLength);

    EVP_CIPHER_CTX_free(ctx);
    return output;
}

// explicit template specialization
template class ChannelEncryption<std::string>;

template class ChannelEncryption<std::vector<uint8_t>>;
