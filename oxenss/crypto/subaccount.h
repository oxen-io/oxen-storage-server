#pragma once

#include <stdexcept>
#include "../common/subaccount_token.h"
#include "../common/pubkey.h"

namespace oxenss {

// Exception types thrown by signed_subaccount_token::verify
struct subaccount_verification_error : std::exception {};
struct subaccount_verification_bad_network : subaccount_verification_error {
    const char* what() const noexcept override { return "subaccount network prefix mismatch"; };
};
struct subaccount_verification_bad_permissions : subaccount_verification_error {
    const char* what() const noexcept override {
        return "subaccount is missing the required permissions";
    };
};
struct subaccount_verification_bad_signature : subaccount_verification_error {
    const char* what() const noexcept override {
        return "subaccount token signature verification failed";
    };
};

// Simple container hold a subaccount token, and an account owner signature of that token; used
// during authentication.
struct signed_subaccount_token {
    subaccount_token token;
    std::array<unsigned char, 64> signature;

    // Verifies that this token & signature are valid for accessing the the account of the given
    // pubkey with (at least) all of the permissions in `required_access` set.  (NB: This does not
    // check for db revocation).
    //
    // - `pubkey` is the account public key
    // - `required_access` are access bits that need to be set (but the token may have additional
    //   flags as well).
    // - `ed_pk` is a pointer to the 32-byte binary ed25519 pubkey for verification; if null then
    //   the pubkey inside `pubkey` is used.  This is intended for mixed x/ed verification, such as
    //   on session ID accounts.
    //
    // Throws something derived from `subaccount_verification_error` on failure.
    void verify(
            const user_pubkey& pubkey,
            subaccount_access required_access,
            const unsigned char* ed_pk = nullptr) const;

    // Same as above, but works on more raw values
    void verify(uint8_t net_prefix, const unsigned char* ed_pk, subaccount_access required_access)
            const;
};

}  // namespace oxenss
