#include <boost/test/unit_test.hpp>
#include <iostream>
#include <ostream>

#include "oxend_key.h"
#include "channel_encryption.hpp"

using namespace oxen;

BOOST_AUTO_TEST_SUITE(encrypt)

constexpr auto plaintext_data = "Grumpy cat says no!"sv;

const auto alice_pubkey = oxen::x25519_pubkey::from_hex("01c7391664840b2ef7126b3709dbac178ba5f3ef2335a62343d5df7da4a11c30");
const auto alice_seckey = oxen::x25519_seckey::from_hex("7d446468c186d6fb3c83365ab77a37b1f9fa3e59eb9788a40ae2e9560f196f30");
const auto bob_pubkey = oxen::x25519_pubkey::from_hex("f7b99da2e25e3c399902641c707ae20ad72b63ed0cc487730ff0b3bcecf18609");
const auto bob_seckey = oxen::x25519_seckey::from_hex("f512f68e81a932aa2ff6d8723baa260a43a6f789d61c91b71f73e4f284e3600a");

BOOST_AUTO_TEST_CASE(cbc) {
    ChannelEncryption alice_box{alice_seckey, alice_pubkey};
    ChannelEncryption bob_box{bob_seckey, bob_pubkey};

    auto ctext_bob = alice_box.encrypt_cbc(plaintext_data, bob_pubkey);
    BOOST_CHECK_EQUAL(ctext_bob.size(), plaintext_data.size() + 29);
    auto ptext_bob = bob_box.decrypt_cbc(ctext_bob, alice_pubkey);

    BOOST_CHECK_EQUAL(ptext_bob, plaintext_data);

    auto ctext_alice = bob_box.encrypt_cbc(plaintext_data, alice_pubkey);
    BOOST_CHECK_EQUAL(ctext_alice.size(), plaintext_data.size() + 29);
    auto ptext_alice = alice_box.decrypt_cbc(ctext_alice, bob_pubkey);

    BOOST_CHECK_EQUAL(ptext_alice, plaintext_data);
}

BOOST_AUTO_TEST_CASE(gcm) {
    ChannelEncryption alice_box{alice_seckey, alice_pubkey};
    ChannelEncryption bob_box{bob_seckey, bob_pubkey};

    auto ctext_bob = alice_box.encrypt_gcm(plaintext_data, bob_pubkey);
    BOOST_CHECK_EQUAL(ctext_bob.size(), plaintext_data.size() + 28);
    auto ptext_bob = bob_box.decrypt_gcm(ctext_bob, alice_pubkey);

    BOOST_CHECK_EQUAL(ptext_bob, plaintext_data);

    auto ctext_alice = bob_box.encrypt_gcm(plaintext_data, alice_pubkey);
    BOOST_CHECK_EQUAL(ctext_alice.size(), plaintext_data.size() + 28);
    auto ptext_alice = alice_box.decrypt_gcm(ctext_alice, bob_pubkey);

    BOOST_CHECK_EQUAL(ptext_alice, plaintext_data);
}

BOOST_AUTO_TEST_CASE(xchacha20) {
    ChannelEncryption alice_box{alice_seckey, alice_pubkey};
    ChannelEncryption bob_box{bob_seckey, bob_pubkey};

    auto ctext_bob = alice_box.encrypt_xchacha20(plaintext_data, bob_pubkey);
    BOOST_CHECK_EQUAL(ctext_bob.size(), plaintext_data.size() + 40);
    auto ptext_bob = bob_box.decrypt_xchacha20(ctext_bob, alice_pubkey);

    BOOST_CHECK_EQUAL(ptext_bob, plaintext_data);

    auto ctext_alice = bob_box.encrypt_xchacha20(plaintext_data, alice_pubkey);
    BOOST_CHECK_EQUAL(ctext_alice.size(), plaintext_data.size() + 40);
    auto ptext_alice = alice_box.decrypt_xchacha20(ctext_alice, bob_pubkey);

    BOOST_CHECK_EQUAL(ptext_alice, plaintext_data);
}

BOOST_AUTO_TEST_SUITE_END()
