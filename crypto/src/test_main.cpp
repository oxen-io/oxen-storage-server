#include "channel_encryption.hpp"
#include <assert.h>
#include <iostream>
#include <sodium.h>

int main() {
    ChannelEncryption<std::string> channel(
        "/Users/sachav/Downloads/identity.private");
    const std::string pubKey =
        "86fe0345719904c47d9d3d24d742d110cab95f9386173057bd59f1c2249da174";
    const std::string plainText = "params\":{\"pubKey\":"
                                  "\"0549b42c7600a25ab9800903630a57f157a1a0f771"
                                  "cac31df559eb13fc5cc0c813\"}}";

    const auto ciphertext = channel.encrypt(plainText, pubKey);
    const auto decrypted = channel.decrypt(ciphertext, pubKey);
    assert(plainText == decrypted);
}
