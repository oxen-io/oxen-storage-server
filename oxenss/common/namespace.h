#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include "formattable.h"

namespace oxen {

enum class namespace_id : int16_t {
    Default = 0,  // Ordinary Session messages
    Min = -32768,
    Max = 32767,

    // Client config storage:
    UserProfile = 2,
    Contacts = 3,
    ConvoInfoVolatile = 4,
    UserGroups = 5,

    // Groups:
    GroupMessages = 11,
    GroupKeys = 12,
    GroupInfo = 13,
    GroupMembers = 14,

    // For "old" closed group messages; allows unauthenticated store *and* retrieval.  Deprecated
    // and will be removed from a future version once no longer used.
    LegacyClosed = -10,
};

constexpr auto to_int(namespace_id ns) {
    return static_cast<std::underlying_type_t<namespace_id>>(ns);
}

// "Public" namespaces are namespaces that anyone can send to, such as the default Session message
// namespace (0) where other people send you messages.
//
// We allow this for every namespace divisible by 10 (0, 10, 400, -1230, etc.)
constexpr bool is_public_inbox_namespace(namespace_id ns) {
    return to_int(ns) % 10 == 0;
}

// "Public outbox" namespaces are namespaces that:
// - can store only one single message at a time; storing a new message automatically removes any
//   existing messages
// - are publicly retrievable: anyone, without authentication, can retrieve messages
// - require the owner's authentication to store to.  (Note that, because of the implicit deletion
//   of existing messages, only "moderator" subaccounts (with the delete bit) can store, but not
//   "normal" subaccounts with just read/write permissions.  Subaccounts may, however, extend the
//   expiry of an existing message).
//
// This is designed to allow unique information -- such as profile data intended to be publicly
// accessible -- to be published to a user's swarm, should a user wish to publish it.
//
// Any *negative* namespace of the form -(20n+1); that is: -1, -21, -981, etc. is a public outbox.
constexpr bool is_public_outbox_namespace(namespace_id ns) {
    const auto n = to_int(ns);
    return n < 0 && -n % 20 == 1;
}

// True if this namespace doesn't require authentication for retrieval: either the public outbox, or
// the legacy closed group namespace.
constexpr bool is_noauth_retrieve_namespace(namespace_id ns) {
    return ns == namespace_id::LegacyClosed || is_public_outbox_namespace(ns);
}

// Unrevokable namespace: negative namespaces ending in "11" (e.g. -11, -211, -12311) have special
// non-revokable retrieve status: that is, a revoked (but otherwise valid) subaccount may still be
// used to retrieve from such a namespace.  This is used in particular by groups to be able to leave
// a message behind for a removed user for them to receive notification of their removal, even after
// their subaccount has been revoked as part of the removal process.
constexpr bool is_unrevocable_namespace(namespace_id ns) {
    const auto n = to_int(ns);
    return n < 0 && -n % 100 == 11;
}

std::string to_string(namespace_id ns);

constexpr auto NAMESPACE_MIN = to_int(namespace_id::Min);
constexpr auto NAMESPACE_MAX = to_int(namespace_id::Max);

template <>
inline constexpr bool to_string_formattable<namespace_id> = true;

}  // namespace oxen
