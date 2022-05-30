#include <oxenss/crypto/signature.h>

#include <catch2/catch.hpp>
#include <oxenc/base64.h>

#include <vector>

using namespace oxen;
using namespace oxen::crypto;

TEST_CASE("signatures - hash generation", "[signature][hash]") {
    std::vector<hash> hashes;

    const std::string inputs[] = {
            "L", "", "FOO", "FOO_", "FO0", "FFO", "FFFFFFFFFFFFFFFFFFFFOOOOOOOOOOOOOO"};
    for (const auto& str : inputs) {
        const auto hash = hash_data(str);
        CHECK(std::find(hashes.begin(), hashes.end(), hash) == hashes.end());
        hashes.push_back(hash);
    }
}

static const auto public_key =
        legacy_pubkey::from_hex("e35b7cf5057845284740af496ec323148db68ac2553a05e4677b96f3afdabcd1");
static const auto secret_key =
        legacy_seckey::from_hex("97fe49c2d436e5a39f8aa2e3374d19b532eecfb2b0367eaa6f703279e34ec102");

TEST_CASE("signatures - it_signs_and_verifies", "[signature][...]") {
    const auto hash = hash_data("This is the payload");
    REQUIRE(secret_key.pubkey() == public_key);
    const auto sig = generate_signature(hash, {public_key, secret_key});
    CHECK(check_signature(sig, hash, public_key));
}

TEST_CASE("signatures - it_signs_and_verifies_encoded_inputs", "[signature][...]") {

    const auto hash = hash_data("This is the payload");
    const auto sig = generate_signature(hash, {public_key, secret_key});

    // convert signature to base64
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());
    const std::string sig_b64 = oxenc::to_base64(raw_sig);

    CHECK(check_signature(signature::from_base64(sig_b64), hash, public_key));
}

TEST_CASE("signatures - it_rejects_wrong_signature", "[signature][...]") {

    const auto hash = hash_data("This is the payload");
    auto sig = generate_signature(hash, {public_key, secret_key});

    // amend signature
    sig.c[4]++;

    CHECK_FALSE(check_signature(sig, hash, public_key));
}
