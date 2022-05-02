#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>
#include <variant>
#include <oxenc/bt_serialize.h>

#include <oxenss/common/pubkey.h>
#include <oxenss/common/namespace.h>

namespace oxen::rpc {

using namespace std::literals;

// Client rpc endpoints, accessible via the HTTPS storage_rpc endpoint, the OMQ
// "storage.whatever" endpoints, and as the final target of an onion request.

/// Thrown when parsing parameters when we encounter missing required fields, invalid value
/// types, etc.  `what()` is designed to be returned to the request initiator.
struct parse_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Common base type decorator of all client rpc endpoint types.
struct endpoint {
    // Loads the rpc request from json.  Throws on error (missing keys, bad values, etc.).
    virtual void load_from(nlohmann::json params) = 0;
    virtual void load_from(oxenc::bt_dict_consumer params) = 0;

    bool b64 = true;  // True if we need to base64-encode values (i.e. for json); false if we
                      // can deal with binary (i.e. bt-encoded)

    virtual ~endpoint() = default;
};

// Base type for no-argument endpoints
struct no_args : endpoint {
    void load_from(nlohmann::json) override {}
    void load_from(oxenc::bt_dict_consumer) override {}
};

/// Base type for a "recursive" endpoint: that is, where the request gets forwarded from the
/// initial swarm member to all other swarm members.
///
/// Recursive requests return per-swarm member results in the "swarm" key; results are endpoint
/// specific, but on failure there will be a `"failed": true` key possibly accompanied by one of
/// the following:
/// - "timeout": true if the inter-swarm request timed out
/// - "code": X if the inter-swarm request returned error code X
/// - "reason": a reason string, e.g. propagating a thrown exception messages
/// - "bad_peer_response": true if the peer returned an unparseable response
/// - "query_failure": true if the database failed to perform the query
struct recursive : endpoint {
    // True on the initial client request, false on forwarded requests
    bool recurse;

    virtual oxenc::bt_value to_bt() const = 0;
};

namespace {
    /// Returns a constexpr std::array of string_views from an arbitrary list of string literals
    /// Used to specify RPC names as:
    /// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
    template <size_t... N>
    constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&... names)[N]) {
        static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
        return {std::string_view{names, N - 1}...};
    }
}  // namespace

/// Stores data in this service node and forwards it to the rest of the storage swarm.  Takes
/// keys of:
/// - `pubkey` (required) contains the pubkey of the recipient, encoded in hex.  Can also use the
///   key name `pubKey` for this.
/// - `timestamp` (required) the timestamp of the message in unix epoch milliseconds, passed as an
///   integer.  Timestamp may not be in the future (though a few seconds tolerance is permitted).
///   For backwards compatibility may be passed as a stringified integer.
/// - `ttl` (required, unless expiry given) the message's lifetime, in milliseconds, passed as a
///   string or stringified integer, relative to the timestamp.  Timestamp+ttl must not be in the
///   past.  For backwards compatibility may be passed as a stringified integer.
/// - `expiry` (required, unless ttl given) the message's expiry time as a unix epoch milliseconds
///   timestamp.  (Unlike ttl, this cannot be passed as a stringified integer).
/// - `data` (required) the message data, encoded in base64 (for json requests).  Max data size is
///   76800 bytes (== 102400 in b64 encoding).  For OMQ RPC requests the value is bytes.
/// - `namespace` (optional) a non-zero integer namespace (from -32768 to 32767) in which to store
///   this message.  Messages in different namespaces are treated as separate storage boxes from
///   untagged messages.  (Note that before the Oxen 10 hardfork (HF 19) this field will be ignored
///   and the message will end up in the default namespace (i.e. namespace 0) regardless of what was
///   specified here.)
///
///   Different IDs have different storage properties:
///   - namespaces divisible by 10 (e.g. 0, 60, -30) allow unauthenticated submission: that is,
///     anyone may deposit messages into them without authentication.  Authentication is required
///     for retrieval (and all other operations).
///   - namespaces -30 through 30 are reserved for current and future Session message storage.
///     Currently in use or planned for use are 0 (DMs), -10 (legacy closed groups), 3 (future v2
///     closed groups), 5 (Session account private metadata).
///   - non-divisible-by-10 namespaces require authentication for all operations, including storage.
///   Omitting the namespace is equivalent to specifying the 0 namespace.
///
/// Authentication parameters: these are required when storing to a namespace not divisible by 10,
/// and must match the pubkey of the storage address.  If provided then the request will be denied
/// if the signature does not match.  Should not be provided when depositing a message in a public
/// receiving (i.e. divisible by 10) namespace.
///
/// - signature -- Ed25519 signature of ("store" || namespace || timestamp), where namespace and
///   timestamp are the base10 expression of the namespace and timestamp values.  Must be base64
///   encoded for json requests; binary for OMQ requests.  For non-05 type pubkeys (i.e. non session
///   ids) the signature will be verified using `pubkey`.  For 05 pubkeys, see the following option.
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from *this* given ed25519 pubkey (which must be
///   64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix) for the signature to be
///   accepted.
/// - sig_timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
///   epoch.  Must be within ±60s of the current time.  (For clients it is recommended to retrieve a
///   timestamp via `info` first, to avoid client time sync issues).  If omitted, `timestamp` is
///   used instead; it is recommended to include this value separately, particularly if a delay
///   between message construction and message submission is possible.
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "hash": the hash of the stored message; will be an unpadded base64-encode blake2b hash of
///       (TIMESTAMP || EXPIRY || PUBKEY || NAMESPACE || DATA), where PUBKEY is in bytes (not hex!);
///       DATA is in bytes (not base64); and NAMESPACE is empty for namespace 0, and otherwise is
///       the decimal representation of the namespace index.
///     - "signature": signature of the returned "hash" value (i.e. not in decoded bytes).  Returned
///       encoded in base64 for JSON requests, raw bytes for OMQ requests.
///     - "already": will be true if a message with this hash was already stored (note that the hash
///       is still included and signed even if this occurs).
///
struct store final : recursive {
    static constexpr auto names() { return NAMES("store"); }

    /// Maximum `data` size in bytes (max acceptable b64 size will be 4/3 of this).
    inline static constexpr size_t MAX_MESSAGE_BODY = 76'800;

    user_pubkey_t pubkey;
    namespace_id msg_namespace = namespace_id::Default;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry;  // computed from timestamp+ttl if ttl was given
    std::string data;                              // always stored here in bytes

    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<std::array<unsigned char, 64>> signature;
    std::optional<std::chrono::system_clock::time_point> sig_ts;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// Retrieves data from this service node. Takes keys of:
/// - `pubkey` (required) the hex-encoded pubkey who is retrieving messages. For backwards
///   compatibility, this can also be specified as `pubKey`
/// - `namespace` (optional) the integral message namespace from which to retrieve messages.  Each
///   namespace forms an independent message storage for the same address.  When specified,
///   authentication *must* be provided.  Omitting the namespace is equivalent to specifying a
///   namespace of 0.  (Note, however, that an explicit namespace of 0 requires authentication,
///   while an implicit namespace of 0 does not during the transition period).
/// - `last_hash` (optional) retrieve messages stored by this storage server since `last_hash` was
///   stored.  Can also be specified as `lastHash`.  An empty string (or null) is treated as an
///   omitted value.
///
/// Authentication parameters: these are optional during a transition period, up until Oxen
/// hard-fork 19, and become required starting there.  During the transition period, *if* provided
/// then the request will be denied if the signature does not match.  If omitted, during the
/// transition period, then messages will be retrieved without authentication.
///
/// - timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
/// - signature -- Ed25519 signature of ("retrieve" || namespace || timestamp) (if using a non-0
///   namespace), or ("retrieve" || timestamp) when fetching from the default namespace.  Both
///   namespace and timestamp are the base10 expressions of the relevant values.  Must be base64
///   encoded for json requests; binary for OMQ requests.
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
struct retrieve final : endpoint {
    static constexpr auto names() { return NAMES("retrieve"); }

    user_pubkey_t pubkey;
    namespace_id msg_namespace{0};
    std::optional<std::string> last_hash;

    bool check_signature = false;  // For transition; delete this once we require sigs always
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::chrono::system_clock::time_point timestamp;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// Retrieves status information about this storage server.  Takes no parameters.
///
/// Returns:
/// - `version` the version of this storage server as a 3-element array, e.g. [2,1,1]
/// - `timestamp` the current time (in milliseconds since unix epoch); clients are recommended to
///   use this rather than local time, especially when submitting delete requests.
///
struct info final : no_args {
    static constexpr auto names() { return NAMES("info"); }
};

/// Deletes specific stored messages and broadcasts the delete request to all other swarm
/// members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - messages -- array of message hash strings (as provided by the storage server) to delete.
///   Message IDs can be from any message namespace(s).
/// - signature -- Ed25519 signature of ("delete" || messages...); this signs the value constructed
///   by concatenating "delete" and all `messages` values, using `pubkey` to sign.  Must be base64
///   encoded for json requests; binary for OMQ requests.
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "deleted": list of hashes of messages that were found and deleted, sorted by ascii value
///     - "signature": signature of:
///             ( PUBKEY_HEX || RMSG[0] || ... || RMSG[N] || DMSG[0] || ... || DMSG[M] )
///       where RMSG are the requested deletion hashes and DMSG are the actual deletion hashes (note
///       that DMSG... and RMSG... will not necessarily be in the same order or of the same length).
///       The signature uses the node's ed25519 pubkey.
struct delete_msgs final : recursive {
    static constexpr auto names() { return NAMES("delete"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::vector<std::string> messages;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

struct namespace_all_t {};
inline constexpr namespace_all_t namespace_all{};
// Variant for holding unspecified, integer, or "all" namespace input.  Unspecified is generally the
// same as an integer of 0 in effect, but the distinction *does* matter for the signature (which
// matches the given arguments, not the implied value).
using namespace_var = std::variant<std::monostate, namespace_id, namespace_all_t>;

constexpr bool is_all(const namespace_var& ns) {
    return std::holds_alternative<namespace_all_t>(ns);
}
constexpr bool is_omitted(const namespace_var& ns) {
    return std::holds_alternative<std::monostate>(ns);
}

// Returns the implied namespace from a namespace_var containing either a monostate (implied
// namespace 0) or specific namespace.  Should not be called on a variant containing an "all" value.
constexpr namespace_id ns_or_default(const namespace_var& ns) {
    if (auto* id = std::get_if<namespace_id>(&ns))
        return *id;
    return namespace_id::Default;
}

// Returns the representation of a provided namespace variant that should have been used in a
// request signature, which is:
// - empty string if namespace unspecified
// - "all" if given as all namespaces
// - "NN" for some explicitly given numeric namespace NN
inline std::string signature_value(const namespace_var& ns) {
    return is_omitted(ns) ? ""s : is_all(ns) ? "all"s : to_string(var::get<namespace_id>(ns));
}

/// Deletes all messages owned by the given pubkey on this SN and broadcasts the delete request
/// to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - namespace -- (optional) the message namespace from which to delete messages.  This is either
///   an integer to delete messages from a specific namespace, or the string "all" to delete all
///   messages from all namespaces.  If omitted, messages are deleted from the default namespace
///   only (namespace 0).
/// - timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
///   epoch.  Must be within ±60s of the current time.  (For clients it is recommended to retrieve a
///   timestamp via `info` first, to avoid client time sync issues).
/// - signature -- an Ed25519 signature of ( "delete_all" || namespace || timestamp ), where
///   `namespace` is the stringified version of the given namespace parameter (i.e. "0" or "-42" or
///   "all"), or the empty string if namespace was not given.  The signature must be signed by the
///   ed25519 pubkey in `pubkey` (omitting the leading prefix).  Must be base64 encoded for json
///   requests; binary for OMQ requests.
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "deleted": if deleting from a single namespace this is a list of hashes of deleted
///       messages from the namespace, sorted by ascii value.  If deleting from all namespaces this
///       is a dict of `{ namespace => [sorted list of hashes] }` key-value pairs.
///     - "signature": signature of:
///           ( PUBKEY_HEX || TIMESTAMP || DELETEDHASH[0] || ... || DELETEDHASH[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace delete the DELETEDHASH
///       values are totally ordered (i.e. among all the hashes deleted regardless of namespace)
struct delete_all final : recursive {
    static constexpr auto names() { return NAMES("delete_all"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point timestamp;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// Deletes all stored messages with a timestamp earlier than the specified value and broadcasts
/// the delete request to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - namespace -- (optional) the message namespace from which to delete messages.  This is either
///   an integer to delete messages from a specific namespace, or the string "all" to delete
///   messages from all namespaces.  If omitted, messages are deleted from the default namespace
///   only (namespace 0).
/// - before -- the timestamp (in milliseconds since unix epoch) for deletion; all stored messages
///   with timestamps <= this value will be deleted.  Should be <= now, but tolerance acceptance
///   allows it to be <= 60s from now.
/// - signature -- Ed25519 signature of ("delete_before" || namespace || before), signed by
///   `pubkey`.  Must be base64 encoded (json) or bytes (OMQ).  `namespace` is the stringified
///   version of the given namespace parameter (i.e. "0" or "-42" or "all"), or the empty string if
///   namespace was not given.
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "deleted": if deleting from a single namespace this is a list of hashes of deleted
///       messages from the namespace, sorted by ascii value.  If deleting from all namespaces this
///       is a dict of `{ namespace => [sorted list of hashes] }` key-value pairs.
///     - "signature": signature of
///           ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace delete the DELETEDHASH
///       values are totally ordered (i.e. among all the hashes deleted regardless of namespace)
struct delete_before final : recursive {
    static constexpr auto names() { return NAMES("delete_before"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point before;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// Updates (shortens) the expiry of all stored messages, and broadcasts the update request to
/// all other swarm members.  Note that this will not extend existing expiries, it will only
/// shorten the expiry of any messages that have expiries after the requested value.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall have their expiries reduced, in hex (66) or bytes
///   (33)
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - namespace -- (optional) the message namespace from which to change message expiries.  This is
///   either an integer to expire messages from a specific namespace, or the string "all" to update
///   messages in all namespaces.  If omitted, the update applies only to messages from the default
///   namespace (namespace 0).
/// - expiry -- the new expiry timestamp (milliseconds since unix epoch).  Should be >= now, but
///   tolerance acceptance allows >= 60s ago.
/// - signature -- signature of ("expire_all" || expiry), signed by `pubkey`.  Must be base64
///   encoded (json) or bytes (OMQ).
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "updated":
///         - if deleting from a single namespace then this is a list of (ascii-sorted) hashes that
///           had their expiries updated to `expiry`; messages that did not exist or that already
///           had an expiry <= the given expiry are not included.
///         - otherwise (i.e. namespace="all") this is a dict of `{ namespace => [sorted hashes] }`
///           pairs of updated-expiry message hashes.
///     - "signature": signature of
///           ( PUBKEY_HEX || EXPIRY || UPDATED[0] || ... || UPDATED[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace expiry update the
///       UPDATED values are totally ordered (i.e. among all the messages updated regardless of
///       namespace)
struct expire_all final : recursive {
    static constexpr auto names() { return NAMES("expire_all"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point expiry;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// Updates (shortens) the expiry of one or more stored messages and broadcasts the update
/// request to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall have their expiries reduced, in hex (66) or bytes
///   (33)
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - messages -- array of message hash strings (as provided by the storage server) to update.
///   Messages can be from any namespace(s).
/// - expiry -- the new expiry timestamp (milliseconds since unix epoch).  Must be >= 60s ago.
/// - signature -- Ed25519 signature of:
///       ("expire" || expiry || messages[0] || ... || messages[N])
///   where `expiry` is the expiry timestamp expressed as a string.  The signature must be base64
///   encoded (json) or bytes (bt).
///
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "updated": ascii-sorted list of hashes of messages that had their expiries updated
///       (messages that already had an expiry <= the given expiry are not included).
///     - "signature": signature of:
///             ( PUBKEY_HEX || EXPIRY || RMSG[0] || ... || RMSG[N] || UMSG[0] || ... || UMSG[M] )
///       where RMSG are the requested expiry hashes and UMSG are the actual updated hashes.  The
///       signature uses the node's ed25519 pubkey.
struct expire_msgs final : recursive {
    static constexpr auto names() { return NAMES("expire"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::vector<std::string> messages;
    std::chrono::system_clock::time_point expiry;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// Retrieves the swarm information for a given pubkey. Takes keys of:
/// - `pubkey` (required) the pubkey to query, in hex (66) or bytes (33).
struct get_swarm final : endpoint {
    static constexpr auto names() { return NAMES("get_swarm", "get_snodes_for_pubkey"); }

    user_pubkey_t pubkey;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// Forwards an RPC request to the this storage server's oxend.  Takes keys of:
///
/// - `endpoint` (required) the public oxend endpoint name such as "ons_resolve". Only accepts
///   whitelisted oxend rpc endpoints; currently supported are:
///     - get_service_nodes
///     - ons_resolve
/// - `params` (optional) dict of parameters to forward to oxend.  Can be omitted or null if no
///   parameters should be passed.
///
/// See oxend rpc documentation (or the oxen-core/src/rpc/core_rpc_server_command_defs.h file) for
/// information on using these oxend rpc endpoints.
struct oxend_request final : endpoint {
    static constexpr auto names() { return NAMES("oxend_request"); }

    std::string endpoint;
    std::optional<nlohmann::json> params;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

// Type wrapper than contains an arbitrary list of types.
template <typename...>
struct type_list {};

// All of the above RPC types; these are loaded into the supported RPC interfaces at startup.
using client_rpc_types = type_list<
        store,
        retrieve,
        delete_msgs,
        delete_all,
        delete_before,
        expire_msgs,
        expire_all,
        get_swarm,
        oxend_request,
        info>;

}  // namespace oxen::rpc
