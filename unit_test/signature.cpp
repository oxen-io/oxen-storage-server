#include "signature.h"
#include "utils.hpp"

#include <boost/beast/core/detail/base64.hpp>
#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_AUTO_TEST_SUITE(signature_unit_test)

BOOST_AUTO_TEST_CASE(it_generates_hashes) {
    using namespace loki;

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

BOOST_AUTO_TEST_CASE(it_signs_and_verifies) {
    using namespace loki;

    const auto hash = hash_data("This is the payload");
    const public_key_t public_key{227, 91,  124, 245, 5,   120, 69,  40,
                                  71,  64,  175, 73,  110, 195, 35,  20,
                                  141, 182, 138, 194, 85,  58,  5,   228,
                                  103, 123, 150, 243, 175, 218, 188, 209};
    const private_key_t secret_key{151, 254, 73,  194, 212, 54, 229, 163,
                                   159, 138, 162, 227, 55,  77, 25,  181,
                                   50,  238, 207, 178, 176, 54, 126, 170,
                                   111, 112, 50,  121, 227, 78, 193, 2};
    lokid_key_pair_t key_pair{secret_key, public_key};
    signature sig;
    generate_signature(hash, key_pair, sig);
    const bool verified = check_signature(sig, hash, public_key);
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(it_signs_and_verifies_encoded_inputs) {
    using namespace loki;

    const auto hash = hash_data("This is the payload");
    const public_key_t public_key{227, 91,  124, 245, 5,   120, 69,  40,
                                  71,  64,  175, 73,  110, 195, 35,  20,
                                  141, 182, 138, 194, 85,  58,  5,   228,
                                  103, 123, 150, 243, 175, 218, 188, 209};
    const private_key_t secret_key{151, 254, 73,  194, 212, 54, 229, 163,
                                   159, 138, 162, 227, 55,  77, 25,  181,
                                   50,  238, 207, 178, 176, 54, 126, 170,
                                   111, 112, 50,  121, 227, 78, 193, 2};
    lokid_key_pair_t key_pair{secret_key, public_key};
    signature sig;
    generate_signature(hash, key_pair, sig);

    // convert signature to base64 and public key to base32z
    std::string raw_sig;
    raw_sig.reserve(sig.c.size() + sig.r.size());
    raw_sig.insert(raw_sig.begin(), sig.c.begin(), sig.c.end());
    raw_sig.insert(raw_sig.end(), sig.r.begin(), sig.r.end());
    const std::string sig_b64 = boost::beast::detail::base64_encode(raw_sig);

    char buf[64] = {0};
    const auto public_key_b32z = util::base32z_encode(public_key, buf);

    bool verified = check_signature(sig_b64, hash, public_key_b32z);
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(it_rejects_wrong_signature) {
    using namespace loki;

    const auto hash = hash_data("This is the payload");
    const public_key_t public_key{227, 91,  124, 245, 5,   120, 69,  40,
                                  71,  64,  175, 73,  110, 195, 35,  20,
                                  141, 182, 138, 194, 85,  58,  5,   228,
                                  103, 123, 150, 243, 175, 218, 188, 209};
    const private_key_t secret_key{151, 254, 73,  194, 212, 54, 229, 163,
                                   159, 138, 162, 227, 55,  77, 25,  181,
                                   50,  238, 207, 178, 176, 54, 126, 170,
                                   111, 112, 50,  121, 227, 78, 193, 2};
    lokid_key_pair_t key_pair{secret_key, public_key};
    signature sig;
    generate_signature(hash, key_pair, sig);

    // amend signature
    sig.c[4]++;

    const bool verified = check_signature(sig, hash, public_key);
    BOOST_CHECK(!verified);
}

BOOST_AUTO_TEST_SUITE_END()
