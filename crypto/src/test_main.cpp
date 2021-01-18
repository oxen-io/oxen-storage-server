#include "channel_encryption.hpp"
#include <assert.h>
#include <iostream>

int main() {
    const std::vector<uint8_t> private_key{
        114, 19,  233, 130, 59,  240, 42,  209, 251, 142, 29,
        59,  200, 89,  234, 154, 202, 12,  29,  44,  180, 111,
        36,  158, 126, 252, 198, 236, 141, 163, 95,  15};
    ChannelEncryption<std::string> channel(private_key);
    const std::string pubKey =
        "86fe0345719904c47d9d3d24d742d110cab95f9386173057bd59f1c2249da174";
    const std::string plainText = "params\":{\"pubKey\":"
                                  "\"0549b42c7600a25ab9800903630a57f157a1a0f771"
                                  "cac31df559eb13fc5cc0c813\"}}";

    const auto ciphertext = channel.encrypt_gcm(plainText, pubKey);
    const auto decrypted = channel.encrypt_gcm(ciphertext, pubKey);
    assert(plainText == decrypted);
}
