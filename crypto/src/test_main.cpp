#include "channel_encryption.hpp"
#include "oxend_key.h"
#include <iostream>
#include <oxenmq/hex.h>

std::string printable(std::string_view in) {
    // Quick, dirty, and inefficient only meant for test code.
    std::string result;
    for (char c : in) {
        if (c >= 0x21 && c <= 0x7e)
            result += c;
        else
            result += "\\x" + oxenmq::to_hex(&c, &c+1);
    }
    return result;
}

int main() {
    oxen::ChannelEncryption channel{oxen::x25519_seckey::from_hex(
            "7213e9823bf02ad1fb8e1d3bc859ea9aca0c1d2cb46f249e7efcc6ec8da35f0f")};

    auto pubKey = oxen::x25519_pubkey::from_hex(
        "86fe0345719904c47d9d3d24d742d110cab95f9386173057bd59f1c2249da174");
    const std::string plainText = "params\":{\"pubKey\":"
                                  "\"0549b42c7600a25ab9800903630a57f157a1a0f771"
                                  "cac31df559eb13fc5cc0c813\"}}";

    const auto ciphertext = channel.encrypt_gcm(plainText, pubKey);
    const auto decrypted = channel.decrypt_gcm(ciphertext, pubKey);
    if (plainText != decrypted) {
        std::cerr << "round-trip GCM encrypt-decrypt failed!\n";
        std::cerr << "orig:   " << printable(plainText) << "\n";
        std::cerr << "result: " << printable(decrypted) << "\n";
        return 1;
    }
    std::cout << "OK\n";
    return 0;
}
