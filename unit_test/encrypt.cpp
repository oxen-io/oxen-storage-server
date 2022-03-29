#include <catch2/catch.hpp>
#include <iostream>
#include <ostream>

#include "channel_encryption.hpp"
#include "oxend_key.h"

namespace oxen {
constexpr auto plaintext_data = "Grumpy cat says no!"sv;

const auto alice_pubkey = oxen::x25519_pubkey::from_hex(
        "01c7391664840b2ef7126b3709dbac178ba5f3ef2335a62343d5df7da4a11c30");
const auto alice_seckey = oxen::x25519_seckey::from_hex(
        "7d446468c186d6fb3c83365ab77a37b1f9fa3e59eb9788a40ae2e9560f196f30");
const auto bob_pubkey = oxen::x25519_pubkey::from_hex(
        "f7b99da2e25e3c399902641c707ae20ad72b63ed0cc487730ff0b3bcecf18609");
const auto bob_seckey = oxen::x25519_seckey::from_hex(
        "f512f68e81a932aa2ff6d8723baa260a43a6f789d61c91b71f73e4f284e3600a");

TEST_CASE("AES-CBC encryption", "[encrypt][cbc]") {
    ChannelEncryption alice_box{alice_seckey, alice_pubkey};
    ChannelEncryption bob_box{bob_seckey, bob_pubkey};

    auto ctext_bob = alice_box.encrypt_cbc(plaintext_data, bob_pubkey);
    CHECK(ctext_bob.size() == plaintext_data.size() + 29);
    auto ptext_bob = bob_box.decrypt_cbc(ctext_bob, alice_pubkey);

    CHECK(ptext_bob == plaintext_data);

    auto ctext_alice = bob_box.encrypt_cbc(plaintext_data, alice_pubkey);
    CHECK(ctext_alice.size() == plaintext_data.size() + 29);
    auto ptext_alice = alice_box.decrypt_cbc(ctext_alice, bob_pubkey);

    CHECK(ptext_alice == plaintext_data);
}

TEST_CASE("AES-GCM encryption", "[encrypt][gcm]") {
    ChannelEncryption alice_box{alice_seckey, alice_pubkey};
    ChannelEncryption bob_box{bob_seckey, bob_pubkey};

    auto ctext_bob = alice_box.encrypt_gcm(plaintext_data, bob_pubkey);
    CHECK(ctext_bob.size() == plaintext_data.size() + 28);
    auto ptext_bob = bob_box.decrypt_gcm(ctext_bob, alice_pubkey);

    CHECK(ptext_bob == plaintext_data);

    auto ctext_alice = bob_box.encrypt_gcm(plaintext_data, alice_pubkey);
    CHECK(ctext_alice.size() == plaintext_data.size() + 28);
    auto ptext_alice = alice_box.decrypt_gcm(ctext_alice, bob_pubkey);

    CHECK(ptext_alice == plaintext_data);
}

TEST_CASE("XChaCha20-Poly1309 encryption", "[encrypt][xchacha20]") {
    ChannelEncryption alice_server{alice_seckey, alice_pubkey};
    ChannelEncryption alice_client{alice_seckey, alice_pubkey, false};
    ChannelEncryption bob_server{bob_seckey, bob_pubkey};
    ChannelEncryption bob_client{bob_seckey, bob_pubkey, false};

    auto ctext_bob = alice_client.encrypt_xchacha20(plaintext_data, bob_pubkey);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    auto ptext_bob = bob_server.decrypt_xchacha20(ctext_bob, alice_pubkey);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_client.decrypt_xchacha20(ctext_bob, alice_pubkey), std::runtime_error);

    auto ctext_alice = bob_client.encrypt_xchacha20(plaintext_data, alice_pubkey);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    auto ptext_alice = alice_server.decrypt_xchacha20(ctext_alice, bob_pubkey);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_client.decrypt_xchacha20(ctext_alice, bob_pubkey), std::runtime_error);

    ctext_bob = alice_server.encrypt_xchacha20(plaintext_data, bob_pubkey);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    ptext_bob = bob_client.decrypt_xchacha20(ctext_bob, alice_pubkey);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_server.decrypt_xchacha20(ctext_bob, alice_pubkey), std::runtime_error);

    ctext_alice = bob_server.encrypt_xchacha20(plaintext_data, alice_pubkey);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    ptext_alice = alice_client.decrypt_xchacha20(ctext_alice, bob_pubkey);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_server.decrypt_xchacha20(ctext_alice, bob_pubkey), std::runtime_error);
}

}  // namespace oxen
