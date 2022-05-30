#pragma once

#include <oxenss/crypto/keys.h>

#include <functional>
#include <string_view>

namespace oxen::rpc {

using oxend_seckeys =
        std::tuple<crypto::legacy_seckey, crypto::ed25519_seckey, crypto::x25519_seckey>;

// Synchronously retrieves SN private keys from oxend via the given oxenmq address.  This
// constructs a temporary OxenMQ instance to do the request (because generally storage server
// will have to re-construct one once we have the private keys).
//
// Returns legacy privkey; ed25519 privkey; x25519 privkey.
//
// Takes an optional callback to invoke immediately before each attempt and immediately after
// each failed attempt: if the callback returns false then get_sn_privkeys aborts, returning a
// tuple of empty keys.
//
// This retries indefinitely until the connection & request are successful, or the callback
// returns false.
oxend_seckeys get_sn_privkeys(
        std::string_view oxend_rpc_address, std::function<bool()> keep_trying = nullptr);

}  // namespace oxen::rpc
