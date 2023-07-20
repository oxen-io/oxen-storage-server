#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string_view>
#include <type_traits>

namespace oxen {

// Length of the pubkey component of a subaccount token
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_PUBKEY = 32;
// Number of bytes for access flags
inline constexpr size_t SUBACCOUNT_TOKEN_LEN_FLAGS = 1;
// Overall subaccount token length
inline constexpr size_t SUBACCOUNT_TOKEN_LENGTH =
        SUBACCOUNT_TOKEN_LEN_PUBKEY + SUBACCOUNT_TOKEN_LEN_FLAGS;

enum class subaccount_access : uint8_t {
    None = 0b0000'0000,
    Read = 0b0000'0001,
    Write = 0b0000'0010,
    Delete = 0b0000'0100,
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

/// A subaccount token is a packed 33-byte string of which the first 32-bytes is an Ed25519 pubkey
/// (which typically is a blinded key derived from a Session ID), and the last byte is a set of
/// permission bits.
///
/// Authenticating using such a subaccount token requires three pieces of data and two
/// verifications:
/// - the subaccount token.
/// - signature of the subaccount token by the account master key.
/// - the usual request signature verifiable via the subaccount token's public key.
struct subaccount_token {
    // The full actual token, in bytes.
    std::array<uint8_t, SUBACCOUNT_TOKEN_LENGTH> token;

    // Returns a basic_string_view<uint8_t> of the full binary token value.  This is the same as
    // `token`, just easier when a string view is needed.
    std::basic_string_view<uint8_t> view() const { return {token.data(), token.size()}; }

    // Returns a string_view of the binary token value.
    std::string_view sview() const {
        return {reinterpret_cast<const char*>(token.data()), token.size()};
    }

    // Returns the Ed25519 pubkey of the current token.
    std::basic_string_view<uint8_t> pubkey() const {
        return view().substr(0, SUBACCOUNT_TOKEN_LENGTH);
    }

    // Returns the flags represented by the current token.
    subaccount_access flags() const {
        return static_cast<subaccount_access>(token[SUBACCOUNT_TOKEN_LENGTH - 1]);
    }

    // Replaces the current flags.
    void set_flags(subaccount_access f) {
        token[SUBACCOUNT_TOKEN_LENGTH - 1] =
                static_cast<std::underlying_type_t<subaccount_access>>(f);
    }

    // Clears all existing flags on the token (including unknown/reserved flags).
    void clear_flags() { set_flags(subaccount_access::None); }

    // Return true if the read/write/delete flag is set in this access token
    bool can_read() const { return (flags() & subaccount_access::Read) == subaccount_access::Read; }
    bool can_write() const {
        return (flags() & subaccount_access::Write) == subaccount_access::Write;
    }
    bool can_delete() const {
        return (flags() & subaccount_access::Delete) == subaccount_access::Delete;
    }

    // Sets the read/write/delete flag on the access token; other flags are left undisturbed.
    void set_read() { set_flags(flags() | subaccount_access::Read); }
    void set_write() { set_flags(flags() | subaccount_access::Write); }
    void set_delete() { set_flags(flags() | subaccount_access::Delete); }

    // Clears the read/write/delete flag on the access token; other flags are left undisturbed.
    void clear_read() { set_flags(flags() & ~subaccount_access::Read); }
    void clear_write() { set_flags(flags() & ~subaccount_access::Write); }
    void clear_delete() { set_flags(flags() & ~subaccount_access::Delete); }
};

// Simple container hold a subaccount token, and a signature of that token; used during
// authentication.
struct signed_subaccount_token {
    subaccount_token token;
    std::array<unsigned char, 64> signature;
};

}  // namespace oxen
