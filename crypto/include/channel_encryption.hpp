#pragma once

#include <string>
#include <string_view>

#include "oxend_key.h"

namespace oxen {

class ChannelEncryption {
  public:
    ChannelEncryption(x25519_seckey private_key)
        : private_key_{std::move(private_key)} {}

    std::string encrypt_cbc(std::string_view plainText, const x25519_pubkey& pubKey) const;

    std::string encrypt_gcm(std::string_view plainText, const x25519_pubkey& pubKey) const;

    std::string decrypt_cbc(std::string_view cipherText, const x25519_pubkey& pubKey) const;

    std::string decrypt_gcm(std::string_view cipherText, const x25519_pubkey& pubKey) const;

  private:
    const x25519_seckey private_key_;
};

}
