#pragma once

#include <cstdint>
#include <string>
#include <vector>

template <typename T>
class ChannelEncryption {
  public:
    ChannelEncryption(const std::string& key_path = "");
    ~ChannelEncryption() = default;

    T encrypt(const T& plainText, const std::string& pubKey) const;

    T decrypt(const T& cipherText, const std::string& pubKey) const;

  private:
    std::vector<uint8_t>
    calculateSharedSecret(const std::vector<uint8_t>& pubKey) const;
    std::vector<uint8_t> private_key;

  public:
    std::vector<uint8_t> public_key;
};
