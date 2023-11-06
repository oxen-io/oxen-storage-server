#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string_view>
#include <type_traits>
#include <stdexcept>

namespace oxenss {

// Number of bytes of the network prefix of the subaccount
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_PREFIX = 1;
inline constexpr size_t SUBACCOUNT_TOKEN_PREFIX_INDEX = 0;
// Number of bytes for subaccount flags
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_FLAGS = 1;
inline constexpr size_t SUBACCOUNT_TOKEN_FLAGS_INDEX =
        SUBACCOUNT_TOKEN_PREFIX_INDEX + SUBACCOUNT_TOKEN_LEN_PREFIX;
// Number of reserved bytes for future capabilities
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_RESERVED = 2;
inline constexpr size_t SUBACCOUNT_TOKEN_RESERVED_INDEX =
        SUBACCOUNT_TOKEN_FLAGS_INDEX + SUBACCOUNT_TOKEN_LEN_FLAGS;
// Length of the pubkey component of a subaccount token
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_PUBKEY = 32;
inline constexpr size_t SUBACCOUNT_TOKEN_PUBKEY_INDEX =
        SUBACCOUNT_TOKEN_RESERVED_INDEX + SUBACCOUNT_TOKEN_LEN_RESERVED;
// Overall subaccount token length
inline constexpr size_t SUBACCOUNT_TOKEN_LENGTH =
        SUBACCOUNT_TOKEN_LEN_PREFIX + SUBACCOUNT_TOKEN_LEN_FLAGS + SUBACCOUNT_TOKEN_LEN_RESERVED +
        SUBACCOUNT_TOKEN_LEN_PUBKEY;

static_assert(
        SUBACCOUNT_TOKEN_LENGTH % 3 == 0,
        "Subaccount token length should be a multiple of 3 to avoid base64 padding");
static_assert(
        SUBACCOUNT_TOKEN_PUBKEY_INDEX + SUBACCOUNT_TOKEN_LEN_PUBKEY == SUBACCOUNT_TOKEN_LENGTH);

enum class subaccount_access : uint8_t {
    // Dummy zero value
    None = 0b0000'0000,
    // Allows read access (and related such as retrieving expiries)
    Read = 0b0000'0001,
    // Allows inserting new messages in any namespace and extending existing expiries
    Write = 0b0000'0010,
    // Allow deletions from any namespace and shortening expiries
    Delete = 0b0000'0100,
    // If set then this key should be allowed to access *any* network prefix for this account (not
    // just the SUBACCOUNT_NETWORK_PREFIX value).  E.g. if granted for ID 03abcd... with this flag
    // then the account key can also be used for authentication for other network prefixes with the
    // same pubkey (08abcd..., aaabcd..., etc.).
    AnyPrefix = 0b000'1000,

    // Future bits are reserved
};

inline subaccount_access operator|(subaccount_access lhs, subaccount_access rhs) {
    return static_cast<subaccount_access>(
            static_cast<std::underlying_type_t<subaccount_access>>(lhs) |
            static_cast<std::underlying_type_t<subaccount_access>>(rhs));
}

inline subaccount_access operator&(subaccount_access lhs, subaccount_access rhs) {
    return static_cast<subaccount_access>(
            static_cast<std::underlying_type_t<subaccount_access>>(lhs) &
            static_cast<std::underlying_type_t<subaccount_access>>(rhs));
}

// Negates subaccount_access; note that this *includes* unknown/reserved bits, and so should
// typically only be used in combination with `&` to avoid unintentionally setting reserved future
// bits.
inline subaccount_access operator~(subaccount_access f) {
    return static_cast<subaccount_access>(
            ~static_cast<std::underlying_type_t<subaccount_access>>(f));
}

static_assert(sizeof(subaccount_access) == SUBACCOUNT_TOKEN_LEN_FLAGS);

/// A subaccount token is a packed 36-byte string of which the first byte is the network domain byte
/// (e.g. 0x05 for Session IDs, 0x03  for closed groups, etc.); the next byte is a set of bit flags
/// governing permissions granted to the subaccount; then two bytes of padding (reserved for future
/// capabilities); and finally the last 32 bytes are the Ed25519 pubkey of the subaccount (which
/// typically is a blinded key derived from a Session ID, though can technically be any Ed25519
/// pubkey).
///
/// Conceptually the subaccount signature is a "note" from the account owner designating another
/// user (the subaccount) permission to access the account, with the flags indicating what they are
/// allowed to do in the account, and the main signature then becomes the sub-user's signature.
///
/// From a verification point of view, when presented with such a note we:
/// - check that the note is signed by the real account owner
/// - check that network id matches (i.e. a signed note granting permission to access 03ffeedd...
///   does not grant access to 04ffeedd..., unless the AnyPrefix flag is set)
/// - check that the user is accessing something that the note says they are allowed to access
/// - check that the request is signed by this user (rather than the usual account owner signature).
///
/// For the technical implementation, authenticating using such a subaccount requires three pieces
/// of data and two verifications:
/// - the subaccount token.
/// - signature of the subaccount token by the account master key.
/// - the usual request signature verifiable via the subaccount token's public key.
struct subaccount_token {
    // The full actual token, in bytes.
    std::array<uint8_t, SUBACCOUNT_TOKEN_LENGTH> token{};

    // Returns a basic_string_view<uint8_t> of the full binary token value.  This is the same as
    // `token`, just easier when a string view is needed.
    std::basic_string_view<uint8_t> view() const { return {token.data(), token.size()}; }

    // Returns a string_view of the binary token value.
    std::string_view sview() const {
        return {reinterpret_cast<const char*>(token.data()), token.size()};
    }

    // Returns the Ed25519 pubkey of the current token.
    std::basic_string_view<uint8_t> pubkey() const {
        return view().substr(SUBACCOUNT_TOKEN_PUBKEY_INDEX, SUBACCOUNT_TOKEN_LEN_PUBKEY);
    }

    // Returns the network prefix of this token.
    uint8_t prefix() const { return token[SUBACCOUNT_TOKEN_PREFIX_INDEX]; }

    // Returns true if this token has permission to access an account with the given network prefix
    // (that is: either the prefixes match, or the subaccount has the AnyPrefix flag).
    bool prefix_allowed(uint8_t net_prefix) const {
        return prefix() == net_prefix || has(subaccount_access::AnyPrefix);
    }

    // Returns the flags represented by the current token.
    subaccount_access flags() const {
        return static_cast<subaccount_access>(token[SUBACCOUNT_TOKEN_FLAGS_INDEX]);
    }

    // Replaces the current flags with the given set of flags.
    void set_flags(subaccount_access f) {
        token[SUBACCOUNT_TOKEN_FLAGS_INDEX] =
                static_cast<std::underlying_type_t<subaccount_access>>(f);
    }

    // Return true if the given access flag is set for this access token
    bool has(subaccount_access flag) const { return (flags() & flag) == flag; }

    // Sets a single access flag without altering other flags.
    void set_flag(subaccount_access flag) { set_flags(flags() | flag); }

    // Clears a single access flag without altering other flags.
    void clear_flag(subaccount_access flag) { set_flags(flags() & ~flag); }
};

}  // namespace oxenss
