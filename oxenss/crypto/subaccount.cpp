#include "subaccount.h"
#include <sodium/crypto_sign_ed25519.h>
#include <cassert>

namespace oxen {

void signed_subaccount_token::verify(
        uint8_t net_prefix, const unsigned char* ed_pk, subaccount_access required_access) const {

    if (!token.prefix_allowed(net_prefix))
        throw subaccount_verification_bad_network{};

    // Check that this token allows whatever access flag(s) are needed for this endpoint
    if ((token.flags() & required_access) != required_access)
        throw subaccount_verification_bad_permissions{};

    assert(ed_pk);

    // Verify that the subaccount token has been signed by the main account owner
    if (0 != crypto_sign_ed25519_verify_detached(
                     signature.data(), token.token.data(), token.token.size(), ed_pk))
        throw subaccount_verification_bad_signature{};
}

void signed_subaccount_token::verify(
        const user_pubkey& pubkey,
        subaccount_access required_access,
        const unsigned char* ed_pk) const {

    const unsigned char* pk = ed_pk;
    if (!pk) {
        assert(pubkey.raw().size() == 32);
        pk = reinterpret_cast<const unsigned char*>(pubkey.raw().data());
    }

    return verify(pubkey.type(), pk, required_access);
}

}  // namespace oxen
