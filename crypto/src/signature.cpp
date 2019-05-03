#include "signature.hpp"
#include "utils.hpp"

extern "C" {
#include "loki/crypto-ops/crypto-ops.h"
}

#include <boost/beast/core/detail/base64.hpp>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/randombytes.h>

#include <cstdint>
#include <string>
#include <cstring> // for memcmp
#include <algorithm>
#include <iterator>

namespace signature {

using ec_point = std::array<uint8_t, 32>;
struct s_comm {
    uint8_t h[32];
    uint8_t key[32];
    uint8_t comm[32];
};

void random_scalar(ec_scalar& k) {
    for (size_t i = 0; i < k.size() / 4; ++i) {
        const uint32_t random = randombytes_random();
        k[i + 0] = (random & 0xFF000000) >> 24;
        k[i + 1] = (random & 0x00FF0000) >> 16;
        k[i + 2] = (random & 0x0000FF00) >> 8;
        k[i + 3] = (random & 0x000000FF) >> 0;
    }
}

bool hash_to_scalar(const void* input, size_t size, ec_scalar& output) {
    if (crypto_generichash_blake2b(output.data(), output.size(),
                                   static_cast<const unsigned char*>(input),
                                   size, nullptr, 0) == -1)
        return false;
    sc_reduce32(output.data());
    return true;
}

hash hash_data(const std::string& data) {
    hash hash{{0}};
    crypto_generichash(hash.data(), hash.size(),
                       reinterpret_cast<const unsigned char*>(data.c_str()),
                       data.size(), nullptr, 0);
    return hash;
}

void generate_signature(const hash& prefix_hash, const public_key& pub,
                        const secret_key& sec, signature& sig) {
    ge_p3 tmp3;
    ec_scalar k;
    s_comm buf;
#if !defined(NDEBUG)
    {
        ge_p3 t;
        public_key t2;
        assert(sc_check(sec.data()) == 0);
        ge_scalarmult_base(&t, sec.data());
        ge_p3_tobytes(t2.data(), &t);
        assert(pub == t2);
    }
#endif
    std::copy(prefix_hash.begin(), prefix_hash.end(), std::begin(buf.h));
    std::copy(pub.begin(), pub.end(), std::begin(buf.key));
try_again:
    random_scalar(k);
    if (k[7] == 0) // we don't want tiny numbers here
        goto try_again;
    ge_scalarmult_base(&tmp3, k.data());
    ge_p3_tobytes(buf.comm, &tmp3);
    hash_to_scalar(&buf, sizeof(s_comm), sig.c);
    if (!sc_isnonzero((const unsigned char*)sig.c.data()))
        goto try_again;
    sc_mulsub(sig.r.data(), sig.c.data(), sec.data(), k.data());
    if (!sc_isnonzero((const unsigned char*)sig.r.data()))
        goto try_again;
}

bool check_signature(const signature& sig, const hash& prefix_hash,
                     const public_key& pub) {
    ge_p2 tmp2;
    ge_p3 tmp3;
    ec_scalar c;
    s_comm buf;
    //    assert(check_key(pub));
    std::copy(prefix_hash.begin(), prefix_hash.end(), std::begin(buf.h));
    std::copy(pub.begin(), pub.end(), std::begin(buf.key));
    if (ge_frombytes_vartime(&tmp3, pub.data()) != 0) {
        return false;
    }
    if (sc_check(sig.c.data()) != 0 || sc_check(sig.r.data()) != 0 ||
        !sc_isnonzero(sig.c.data())) {
        return false;
    }
    ge_double_scalarmult_base_vartime(&tmp2, sig.c.data(), &tmp3, sig.r.data());
    ge_tobytes(buf.comm, &tmp2);
    static const ec_point infinity = {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    if (memcmp(buf.comm, &infinity, 32) == 0)
        return false;
    hash_to_scalar(&buf, sizeof(s_comm), c);
    sc_sub(c.data(), c.data(), sig.c.data());
    return sc_isnonzero(c.data()) == 0;
}

bool check_signature(const std::string& signature, const hash& hash,
                     const std::string& public_key_b32z) {
    // convert signature
    const std::string raw_signature =
        boost::beast::detail::base64_decode(signature);
    struct signature sig;
    std::copy_n(raw_signature.begin(), sig.c.size(), sig.c.begin());
    std::copy_n(raw_signature.begin() + sig.c.size(), sig.r.size(),
                sig.r.begin());

    // convert public key
    public_key public_key;
    if (!util::base32z_decode(public_key_b32z, public_key))
        return false;

    return check_signature(sig, hash, public_key);
}

} // namespace signature
