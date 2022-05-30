#include "signature.h"

extern "C" {
#include "oxen/crypto-ops/hash-ops.h"
}

#include <oxenc/base64.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>

static_assert(crypto_generichash_BYTES == oxen::crypto::HASH_SIZE, "Wrong hash size!");

namespace oxen::crypto {

using ec_point = std::array<unsigned char, 32>;
struct s_comm {
    unsigned char h[32];
    unsigned char key[32];
    unsigned char comm[32];
};

static ec_scalar monero_hash_to_scalar(const void* input, size_t size) {
    // We're trying to be backwards compatible with Monero's approach here, which is to
    // calculate H mod L from a 32-byte H.  sodium reduces a 64-byte value, however, so will
    // fill it with 0s to get the same result.  (This is crappy, but to use a 64-byte hash would
    // break backwards compatibility).
    unsigned char hash[64] = {0};
    cn_fast_hash(input, size, reinterpret_cast<char*>(hash));
    ec_scalar result;
    crypto_core_ed25519_scalar_reduce(result.data(), hash);
    return result;
}

hash hash_data(std::string_view data) {
    hash hash;
    crypto_generichash(
            hash.data(),
            hash.size(),
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            nullptr,
            0);
    return hash;
}

// Concatenate a bunch of trivial types together into a std::array
template <typename... T, typename Array = std::array<unsigned char, (sizeof(T) + ...)>>
static Array concatenate(const T&... v) {
    static_assert((std::is_trivial_v<T> && ...));
    Array result;
    unsigned char* ptr = result.data();
    ((std::memcpy(ptr, reinterpret_cast<const void*>(&v), sizeof(T)), ptr += sizeof(T)), ...);
    return result;
}

// Blake2B hash some trivial types together
template <size_t S, typename... T>
static std::array<unsigned char, S> hash_concatenate(const T&... v) {
    std::array<unsigned char, S> h;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, h.size());
    (crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&v), sizeof(T)), ...);
    crypto_generichash_final(&state, h.data(), h.size());
    return h;
}

// With straight Ed25519 sigs this wouldn't be necessary (because sodium clamps things for us),
// but Monero sigs require things to be able to be multiplied *without* clamping (because Monero
// crypto is screwed up by design), so the onus is on the signer to clamp scalars directly.
void clamp(ec_scalar& s) {
    s[0] &= 248;
    s[31] &= 63;
    s[31] |= 64;
}

signature generate_signature(const hash& prefix_hash, const legacy_keypair& keys) {
    /* Generate a non-standard Monero-compatible signature.  This is different from an standard
     * Ed25519 signature for no good reason (i.e. Monero NIH), but we can't change it because we
     * would break backwards compatibility.
     *
     * Monero generation is as follows:
     *
     *     Given M = H(msg)
     *     x = random scalar
     *     X = xG
     *     c = H(M || A || X)
     *
     * where H is cn_fast_hash.  The signature for this is computed as:
     *
     *     r = x - ac
     *
     * with final signature: (c, r)
     *
     * But this relies on a random scalar x, which is undesirable; Ed25519, in contrast, gets x
     * from H(S
     * || M) where S is the second half of the SHA512 hash of the seed.  (Monero keys throw away
     * the seed and only keep a just because NIH again).
     *
     * So we aim to be Ed25519-like in terms of a hash of a deterministic value rather than a
     * random number, but keeping things Monero compatible, so we do:
     *
     *     x = H[512](H[256](a) || A || M)
     *
     * where H[N] is a N-bit Blake2b hash; we reduce and clamp the outer hash to get x, and
     * otherwise keep things the same to remain Monero sig compatible.  (Effectively we are
     * replacing the RNG with the deterministic hash function).
     */
    signature sig;

    const auto& [pubkey, seckey] = keys;
    crypto_generichash(
            sig.r.data(),
            sig.r.size(),
            seckey.data(),
            seckey.size(),
            nullptr,
            0);  // use r as tmp storage
    auto xH = hash_concatenate<64>(sig.r /*H(a)*/, pubkey /*A*/, prefix_hash /*M*/);

    ec_scalar x;
    crypto_core_ed25519_scalar_reduce(x.data(), xH.data());
    clamp(x);

    ec_point X;
    crypto_scalarmult_ed25519_base_noclamp(X.data(), x.data());
    auto M_A_X = concatenate(prefix_hash, pubkey, X);
    sig.c = monero_hash_to_scalar(M_A_X.data(), M_A_X.size());
    crypto_core_ed25519_scalar_mul(sig.r.data(), seckey.data(), sig.c.data());  // r == ac
    crypto_core_ed25519_scalar_sub(sig.r.data(), x.data(), sig.r.data());  // r = x - r (= x - ac)
    return sig;
}

bool check_signature(const signature& sig, const hash& prefix_hash, const legacy_pubkey& pub) {
    /* Monero-style signature verification (which is different from Ed25519 because Monero NIH).
     *
     * given signature (c, r), message hash M, pubkey A, and basepoint G:
     *     X = rG + cA
     *     Check: H(M||A||X) == c
     */
    ec_point X, cA;
    if (0 != crypto_scalarmult_ed25519_base_noclamp(X.data(), sig.r.data()))
        return false;
    if (0 != crypto_scalarmult_ed25519_noclamp(cA.data(), sig.c.data(), pub.data()))
        return false;
    if (0 != crypto_core_ed25519_add(X.data(), X.data(), cA.data()))
        return false;
    if (1 != crypto_core_ed25519_is_valid_point(X.data()))
        return false;

    // H(M||A||X):
    auto M_A_X = concatenate(prefix_hash, pub, X);
    auto expected_c = monero_hash_to_scalar(M_A_X.data(), M_A_X.size());
    return 0 == sodium_memcmp(expected_c.data(), sig.c.data(), expected_c.size());
}

signature signature::from_base64(std::string_view signature_b64) {
    if (!oxenc::is_base64(signature_b64))
        throw std::runtime_error{"Invalid data: not base64-encoded"};

    // 64 bytes bytes -> 86/88 base64 encoded bytes with/without padding
    if (!(signature_b64.size() == 86 ||
          (signature_b64.size() == 88 && signature_b64.substr(86) == "==")))
        throw std::runtime_error{"Invalid data: b64 data size does not match signature size"};

    // convert signature
    signature sig;
    static_assert(sizeof(sig) == 64);
    oxenc::from_base64(
            signature_b64.begin(), signature_b64.end(), reinterpret_cast<unsigned char*>(&sig));
    return sig;
}

}  // namespace oxen::crypto
