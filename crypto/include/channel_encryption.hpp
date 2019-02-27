#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct evp_pkey_st;

template <typename T>
class ChannelEncryption {
  public:
    ChannelEncryption(const std::string& identityPrivatePath = "");
    ~ChannelEncryption() = default;

    T encrypt(const T& plainText, const std::string& pubkey) const;

    T decrypt(const T& cipherText, const std::string& pubkey) const;

  private:
    std::vector<uint8_t>
    calculateSharedSecret(const std::vector<uint8_t>& pubkey) const;
    std::vector<uint8_t> privateKey;
};
