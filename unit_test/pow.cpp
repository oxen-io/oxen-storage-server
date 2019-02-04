#include "pow.hpp"
#include "utils.hpp"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(pow)

BOOST_AUTO_TEST_CASE(util_parses_a_valid_ttl) {
    uint64_t ttl;
    BOOST_CHECK_EQUAL(util::parseTTL("0", ttl), true);
    BOOST_CHECK_EQUAL(ttl, 0);

    BOOST_CHECK_EQUAL(util::parseTTL("1", ttl), true);
    BOOST_CHECK_EQUAL(ttl, 1);

    BOOST_CHECK_EQUAL(util::parseTTL("1000", ttl), true);
    BOOST_CHECK_EQUAL(ttl, 1000);
    // Maximum time to live of 4 days
    BOOST_CHECK_EQUAL(util::parseTTL("345600", ttl), true);
    BOOST_CHECK_EQUAL(ttl, 345600);

    BOOST_CHECK_EQUAL(util::parseTTL("345601", ttl), false);
    BOOST_CHECK_EQUAL(util::parseTTL("-1", ttl), false);
    BOOST_CHECK_EQUAL(util::parseTTL("abcvs", ttl), false);
    BOOST_CHECK_EQUAL(util::parseTTL("", ttl), false);
}

BOOST_AUTO_TEST_CASE(it_checks_a_valid_pow) {
    const auto nonce = "AAAAAAABBCE=";
    const auto timestamp = "1549252654";
    const auto ttl = "345600";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4d";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AQ==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), true);
}

BOOST_AUTO_TEST_CASE(it_checks_an_invalid_nonce) {
    const auto nonce = "AAAAAAABBCD=";
    const auto timestamp = "1549252654";
    const auto ttl = "345600";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4d";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AQ==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), false);
}

BOOST_AUTO_TEST_CASE(it_checks_an_invalid_timestamp) {
    const auto nonce = "AAAAAAABBCE=";
    const auto timestamp = "1549252653";
    const auto ttl = "345600";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4d";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AQ==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), false);
}

BOOST_AUTO_TEST_CASE(it_checks_an_invalid_ttl) {
    const auto nonce = "AAAAAAABBCE=";
    const auto timestamp = "1549252654";
    const auto ttl = "345601";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4d";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AQ==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), false);
}

BOOST_AUTO_TEST_CASE(it_checks_an_invalid_pubkey) {
    const auto nonce = "AAAAAAABBCE=";
    const auto timestamp = "1549252654";
    const auto ttl = "345600";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4c";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AQ==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), false);
}

BOOST_AUTO_TEST_CASE(it_checks_an_invalid_data) {
    const auto nonce = "AAAAAAABBCE=";
    const auto timestamp = "1549252654";
    const auto ttl = "345600";
    const auto pubkey =
        "05d5970e75efb8e8daccd4d07f5f59e744c3aea25cec8bfa3e43674c4a55875f4d";
    const auto data =
        "CAESvgMKA1BVVBIPL2FwaS92MS9tZXNzYWdlGqIDCGUSQjA1ZDU5NzBlNzVlZmI4ZThkYW"
        "NjZDRkMDdmNWY1OWU3NDRjM2FlYTI1Y2VjOGJmYTNlNDM2NzRjNGE1NTg3NWY0ZDgBKNPR"
        "nbWLLULQAvG1sbxpwQY7xXBBWLvYDDtHNBpHtxAMim7+"
        "iSqYYfWvwrobXbUSMP55nAiIUr6iJtvM4OzQoZSV/"
        "zCz5tN9T5tKAvkiVkTyAXva7Re8BO8HX3ra+zPWDsXYw12w9XA4cxY95Y/"
        "6agyMjNDAhj2bhUCMiZNd8dpl5VvKxwFKdxP4zVruKRdAaJy1/xB1gCfZ/hkh2xX90n/"
        "4p4SlPj/XGmjSQ73h6PWm5/"
        "qb2tPNmpkb6uuPD3GpZzxxf4pyMETwhhyruJ6KLxV0eUYh5haHxgjJbs+"
        "OcwjoNpGOEhDCgThcQait2Iyb4ahMWVSjt9vxrfL/7I3HbFtMT+En1J7RutRkWX6YvGHN/"
        "gJApKpfGatKZAwdnUeZy+EUTuZnRzvSLOwOL6HsOFvuq4k3gQ5v5+"
        "ZPfNxSO9T6JvrGzRxofo7edadxn/hqi6dkHU7koHNAjSD2AP==";
    std::string messageHash;
    BOOST_CHECK_EQUAL(
        checkPoW(nonce, timestamp, ttl, pubkey, data, messageHash), false);
}

BOOST_AUTO_TEST_SUITE_END()
