#pragma once

#include "oxend_key.h"
#include <string_view>

#include <oxenmq/oxenmq.h>
#include <oxenmq/hex.h>

namespace oxen {

using oxend_seckeys = std::tuple<legacy_seckey, ed25519_seckey, x25519_seckey>;

// Synchronously retrieves SN private keys from oxend via the given oxenmq address.  This constructs
// a temporary OxenMQ instance to do the request (because generally storage server will have to
// re-construct one once we have the private keys).
//
// Returns legacy privkey; ed25519 privkey; x25519 privkey.
//
// This retries indefinitely until the connection & request are successful.
oxend_seckeys get_sn_privkeys(std::string_view oxend_rpc_address);

}
