#include <catch2/catch.hpp>
#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>

using namespace std::literals;
using namespace oxenss::crypto;

constexpr auto plaintext_data = "Grumpy cat says no!"sv;

const auto alice_keys = x25519_keypair::from_secret_hex(
        "7d446468c186d6fb3c83365ab77a37b1f9fa3e59eb9788a40ae2e9560f196f30");
const auto bob_keys = x25519_keypair::from_secret_hex(
        "f512f68e81a932aa2ff6d8723baa260a43a6f789d61c91b71f73e4f284e3600a");

TEST_CASE("AES-CBC encryption", "[encrypt][cbc]") {
    ChannelEncryption alice_box{alice_keys};
    ChannelEncryption bob_box{bob_keys};

    auto ctext_bob = alice_box.encrypt_cbc(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 29);
    auto ptext_bob = bob_box.decrypt_cbc(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    auto ctext_alice = bob_box.encrypt_cbc(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 29);
    auto ptext_alice = alice_box.decrypt_cbc(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);
}

TEST_CASE("AES-GCM encryption", "[encrypt][gcm]") {
    ChannelEncryption alice_box{alice_keys};
    ChannelEncryption bob_box{bob_keys};

    auto ctext_bob = alice_box.encrypt_gcm(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 28);
    auto ptext_bob = bob_box.decrypt_gcm(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    auto ctext_alice = bob_box.encrypt_gcm(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 28);
    auto ptext_alice = alice_box.decrypt_gcm(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);
}

TEST_CASE("XChaCha20-Poly1309 encryption", "[encrypt][xchacha20]") {
    ChannelEncryption alice_server{alice_keys};
    ChannelEncryption alice_client{alice_keys, false};
    ChannelEncryption bob_server{bob_keys};
    ChannelEncryption bob_client{bob_keys, false};

    auto ctext_bob = alice_client.encrypt_xchacha20(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    auto ptext_bob = bob_server.decrypt_xchacha20(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_client.decrypt_xchacha20(ctext_bob, alice_keys.pub), std::runtime_error);

    auto ctext_alice = bob_client.encrypt_xchacha20(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    auto ptext_alice = alice_server.decrypt_xchacha20(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_client.decrypt_xchacha20(ctext_alice, bob_keys.pub), std::runtime_error);

    ctext_bob = alice_server.encrypt_xchacha20(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    ptext_bob = bob_client.decrypt_xchacha20(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_server.decrypt_xchacha20(ctext_bob, alice_keys.pub), std::runtime_error);

    ctext_alice = bob_server.encrypt_xchacha20(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    ptext_alice = alice_client.decrypt_xchacha20(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_server.decrypt_xchacha20(ctext_alice, bob_keys.pub), std::runtime_error);
}
