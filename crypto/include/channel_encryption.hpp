#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Why is this even a template??
template <typename T>
class ChannelEncryption {
  public:
    ChannelEncryption(const std::vector<uint8_t>& private_key);
    ~ChannelEncryption() = default;

    T encrypt_cbc(const T& plainText, const std::string& pubKey) const;

    T encrypt_gcm(const T& plainText, const std::string& pubKey) const;

    T decrypt_cbc(const T& cipherText, const std::string& pubKey) const;

    T decrypt_gcm(const T& cipherText, const std::string& pubKey) const;

  private:
    const std::vector<uint8_t> private_key_;
};
