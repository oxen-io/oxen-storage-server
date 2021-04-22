#include "signature.h"

#include <oxenmq/base32z.h>
#include <oxenmq/base64.h>
#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_AUTO_TEST_SUITE(signature_unit_test)

BOOST_AUTO_TEST_CASE(it_generates_hashes) {
    using namespace oxen;

    std::vector<hash> hashes;

    const std::string inputs[] = {"L",
                                  "",
                                  "FOO",
                                  "FOO_",
                                  "FO0",
                                  "FFO",
                                  "FFFFFFFFFFFFFFFFFFFFOOOOOOOOOOOOOO"};
    for (const auto& str : inputs) {
        const auto hash = hash_data(str);
        const bool unique =
            std::find(hashes.begin(), hashes.end(), hash) == hashes.end();
        BOOST_CHECK(unique);
        hashes.push_back(hash);
    }
}

static const auto public_key = oxen::legacy_pubkey::from_hex(
            "e35b7cf5057845284740af496ec323148db68ac2553a05e4677b96f3afdabcd1");
static const auto secret_key = oxen::legacy_seckey::from_hex(
            "97fe49c2d436e5a39f8aa2e3374d19b532eecfb2b0367eaa6f703279e34ec102");

BOOST_AUTO_TEST_CASE(it_signs_and_verifies) {
    using namespace oxen;
    const auto hash = hash_data("This is the payload");
    BOOST_REQUIRE_EQUAL(secret_key.pubkey(), public_key);
    const auto sig = generate_signature(hash, {public_key, secret_key});
    const bool verified = check_signature(sig, hash, public_key);
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(it_signs_and_verifies_encoded_inputs) {
    using namespace oxen;

    const auto hash = hash_data("This is the payload");
    const auto sig = generate_signature(hash, {public_key, secret_key});

    // convert signature to base64
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());
    const std::string sig_b64 = oxenmq::to_base64(raw_sig);

    bool verified = check_signature(signature::from_base64(sig_b64), hash,
            public_key);
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(it_rejects_wrong_signature) {
    using namespace oxen;

    const auto hash = hash_data("This is the payload");
    auto sig = generate_signature(hash, {public_key, secret_key});

    // amend signature
    sig.c[4]++;

    const bool verified = check_signature(sig, hash, public_key);
    BOOST_CHECK(!verified);
}

BOOST_AUTO_TEST_SUITE_END()
