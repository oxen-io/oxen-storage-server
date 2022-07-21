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
#include <oxenss/common/type_list.h>

namespace oxen::snode {
class ServiceNode;
}

namespace oxen::rpc {

using namespace std::literals;

constexpr std::string_view SUBKEY_HASH_KEY = "OxenSSSubkey"sv;

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
///   untagged messages.
/// - `subkey` (optional) if provided this is a 32-byte subkey value, encoded base64 or hex (for
///   json requests; bytes, for bt-encoded requests), to use for subkey signature verification
///   instead of using `pubkey` directly.  Denoting this value as `c` and `pubkey` as `A`, the
///   signature verification will use public key value `D=(c+H(c‖A))A` to verify the request
///   signature instead of `A`.  `H(.)` here is 32-byte BLAKE2b with a key of the 12-byte ascii
///   string `OxenSSSubkey`. The client must therefore sign using `d=a(c+H(c‖A))`, where this `d`
///   value has been calculated and provided securely to the sub-user by an owner of the account
///   (i.e. someone with master secret key `a`).  Though `c` can be any cryptographically secure
///   32-byte value, it is recommended to use `c=H(A‖S)`, where `S` is the user's pubkey.
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
/// - signature -- Ed25519 signature of ("store" || namespace || sig_timestamp), where namespace and
///   sig_timestamp are the base10 expression of the namespace and sig_timestamp values.  Must be
///   base64 encoded for json requests; binary for OMQ requests.  For non-05 type pubkeys (i.e. non
///   session ids) the signature will be verified using `pubkey`.  For 05 pubkeys, see the following
///   option.
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from *this* given ed25519 pubkey (which must be
///   64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix) for the signature to be
///   accepted.
/// - sig_timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
///   epoch, used in the authentication signature.  Must be within ±60s of the current time.  (For
///   clients it is recommended to retrieve a timestamp via `info` first, to avoid client time sync
///   issues).  If omitted, `timestamp` is used instead; it is recommended to include this value
///   separately, particularly if a delay between message construction and message submission is
///   possible.
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
    std::optional<std::array<unsigned char, 32>> subkey;
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
///   namespace of 0.
/// - `last_hash` (optional) retrieve messages stored by this storage server since `last_hash` was
///   stored.  Can also be specified as `lastHash`.  An empty string (or null) is treated as an
///   omitted value.
/// - `subkey` (optional) allows retrieval using a derived subkey for authentication.  See `store`
///   for details on how this works.
/// - `max_count`/`max_size` (optional) these two integer values control how many messages to
///   retrieve.  `max_count` takes an absolute count; at most the given value will be returned, when
///   specified.  `max_size` specifies a maximum aggregate size of messages to return (in bytes, if
///   positive).  `max_size` may be specified as `-1` to indicate the maximum size supported in a
///   single network request (minus some overhead allowance); -2 indicates half the maximum size, -3
///   indicates 1/3 the maximum, etc.  Currently the maximum retrieval size is 7.8MB, but this could
///   change in the future.
///
///   When batching multiple retrieve requests together it is highly recommended to use a negative
///   value to avoid exceeding the network size limit: e.g. if retrieving from 5 different
///   namespaces then specify `"max_size": -5` on each of them to ensure that, if all are full, you
///   will not exceed network limits.
///
///   When both `max_count` and `max_size` are specified then the returned message count will not
///   exceed either limit.
///
///   When neither `max_count` nor `max_size` are specified then the request is equivalent to
///   omitting `max_count` and specifying `max_size` as -5 (i.e. return up to 1/5 of the network max
///   transmission size at a time).
///
///   Note that regardless of the two values the response will always include at least one message,
///   even if it would exceed the given maximum size.
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
///
/// On success, returns a dict containing key "messages" with value of a list of message details,
/// and key "more" with a boolean value indicating whether there were more messages (i.e. results
/// were truncated because of the requested or default limits).  Each message details value is a
/// dict containing keys:
///
/// - "hash" -- the message hash
/// - "timestamp" -- the timestamp when the message was deposited
/// - "expiry" -- the timestamp when the message is currently scheduled to expire
/// - "data" -- the message data; b64-encoded for json, bytes for bt-encoded requests.
///
/// Messages order is such that the hash of the last message is the appropriate value to provide as
/// a future "last_hash" value, but otherwise no particular ordering is guaranteed.
struct retrieve final : endpoint {
    static constexpr auto names() { return NAMES("retrieve"); }

    user_pubkey_t pubkey;
    std::optional<std::array<unsigned char, 32>> subkey;
    namespace_id msg_namespace{0};
    std::optional<std::string> last_hash;
    std::optional<int> max_count;
    std::optional<int> max_size;

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
/// - required -- if provided and set to true then require that at least one given message is
///   deleted from at least one swarm member for a 200 response; otherwise return a 404.  When this
///   field is omitted (or false) the response will be a 200 OK even if none of the messages
///   existed.
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
    bool required = false;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

struct namespace_all_t {};
inline constexpr namespace_all_t namespace_all{};

// Variant for holding an integer namespace or "all" namespace input.
using namespace_var = std::variant<namespace_id, namespace_all_t>;

constexpr bool is_all(const namespace_var& ns) {
    return std::holds_alternative<namespace_all_t>(ns);
}
constexpr bool is_default(const namespace_var& ns) {
    auto* n = std::get_if<namespace_id>(&ns);
    return n && *n == namespace_id::Default;
}

// Returns the representation of a provided namespace variant that should have been used in a
// request signature, which is:
// - empty string if default namespace (either unspecified, or explicitly given as 0)
// - "all" if given as all namespaces
// - "NN" for some explicitly given non-default numeric namespace NN
inline std::string signature_value(const namespace_var& ns) {
    return is_default(ns) ? ""s : is_all(ns) ? "all"s : to_string(var::get<namespace_id>(ns));
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
///   `namespace` is the empty string for the default namespace (whether explicitly specified or
///   not), and otherwise the stringified version of the namespace parameter (i.e. "99" or "-42" or
///   "all").  The signature must be signed by the ed25519 pubkey in `pubkey` (omitting the leading
///   prefix).  Must be base64 encoded for json requests; binary for OMQ requests.
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
///   version of the given non-default namespace parameter (i.e. "-42" or "all"), or the empty
///   string for the default namespace (whether explicitly given or not).
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

/// Updates (shortens) the expiry of all stored messages, and broadcasts the update request to all
/// other swarm members.  Note that this will not extend existing expiries, it will only shorten the
/// expiry of any messages that have expiries after the requested value.  (To extend expiries of one
/// or more individual messages use the `expire` endpoint).
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
/// - signature -- signature of ("expire_all" || namespace || expiry), signed by `pubkey`.  Must be
///   base64 encoded (json) or bytes (OMQ).  namespace should be the stringified namespace for
///   non-default namespace expiries (i.e. "42", "-99", "all"), or an empty string for the default
///   namespace (whether or not explicitly provided).
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "updated":
///         - if expiring from a single namespace then this is a list of (ascii-sorted) hashes that
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

/// Updates (shortens or extends) the expiry of one or more stored messages and broadcasts the
/// update request to all other swarm members.
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
/// - expiry -- the new expiry timestamp (milliseconds since unix epoch).  Must be >= 60s ago.  This
///   can be used to extend expiries instead of just shortening them.  The expiry can be extended to
///   at most the maximum TTL (14 days) from now; specifying a later timestamp will be truncated to
///   the maximum.
/// - signature -- Ed25519 signature of:
///       ("expire" || expiry || messages[0] || ... || messages[N])
///   where `expiry` is the expiry timestamp expressed as a string.  The signature must be base64
///   encoded (json) or bytes (bt).
///
///
/// Returns dict of:
/// - "swarms" dict mapping ed25519 pubkeys (in hex) of swarm members to dict values of:
///     - "failed" and other failure keys -- see `recursive`.
///     - "updated": ascii-sorted list of hashes of messages that had their expiries updated.
///     - "expiry": the expiry timestamp that was applied (which might be different from the request
///       expiry, e.g. if the requested value exceeded the permitted TTL).
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

// All of the RPC types that can be invoked as a regular request: either directly, or inside a
// batch.  This excludes the meta-requests like batch/sequence/ifelse (since those nest other
// requests within them).
using client_rpc_subrequests = type_list<
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

using client_subrequest = type_list_variant_t<client_rpc_subrequests>;

/// Batch requests: executes a series of sub-requests, collecting and returning the individual
/// responses.  Note that authentication signatures are required for *each* subrequest as described
/// elsewhere in this documentation, not on the outer batch request itself.
///
/// Note that requests may be performed in parallel or out of order; if you need sequential requests
/// use "sequence" instead.
///
/// This request takes an object containing a single key "requests" which contains a list of 1 to 5
/// elements to invoke up to 5 subrequests.  Each element is a dict containing keys:
///
/// - "method" -- the method name, e.g. "retrieve".
/// - "params" -- the parameters to pass to the subrequest.
///
/// "params" must include any required pubkeys/signatures for the individual subrequest.
///
/// Returned is a dict with key "results" containing a list of the same length of the request, which
/// each element contains the subrequest response to the subrequest in the same position, in a dict
/// containing:
///
/// - "code" -- the numeric response code (e.g. 200 for a typical success)
/// - "body" -- the response value (usually a dict).
///
/// For example, to invoke rpc endpoint "foo" with parameters {"z": 3} and endpoint "bar" with
/// parameters {"z": 2} you would invoke the batch endpoint with parameter:
///
///     {"requests": [{"method": "foo", "params": {"z": 3}}, {"method": "bar", "params": {"z": 2}}]}
///
/// and would get a reply such as:
///
///     {"results": [{"code": 200, "body": {"z_plus_2": 5}}, {"code": 404, "no such z=2 found!"}]}
///
/// Note that, when making the request via HTTP JSON RPC, this is encapsulated inside an outer
/// method/params layer, so the full request would be something like:
///
///     {
///       "method": "batch",
///       "params": {
///         "requests": [
///           { "method": "one", "params": {"z": 1} },
///           { "method": "two", "params": {"y": 2} }
///         ]
///       }
///     }
///
/// The batch request itself returns a 200 status code if the batch was processed, regardless of the
/// return value of the individual subrequests (i.e. you get a 200 back even if all subrequests
/// returned error codes).  Error statuses are returned only for bad batch requests (e.g. missing
/// method/params arguments, invalid/unparseable subrequests, or too many subrequests).
///
/// Note that batch requests may not recurse (i.e. you cannot invoke the batch endpoint as a batch
/// subrequest).
///
struct batch : endpoint {
    static constexpr auto names() { return NAMES("batch"); }

    std::vector<client_subrequest> subreqs;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// Sequence: this works similarly to batch (and takes the same arguments) but unlike batch it
/// processes the requests sequentially and aborts processing further requests if an earlier request
/// fails (i.e. returns a non-2xx status code).
///
/// For example, if you execute sequence method1, method2, method3 and method2 returns status code
/// 456 then method3 is not executed at all, and the result will contain 2 responses: the successful
/// method1 response, and the method2 failure, but no responses after the failure.
///
struct sequence : batch {
    static constexpr auto names() { return NAMES("sequence"); }
};

struct ifelse;

// All of the RPC types that can be invoked as top-level requests, i.e. all of the subrequest types
// (which are invokable via batch/sequence), plus batch, sequence, and ifelse (which are not
// batch-invokable).  These are loaded into the supported RPC interfaces at startup.
using client_rpc_types = type_list_append_t<client_rpc_subrequests, batch, sequence, ifelse>;

using client_request = type_list_variant_t<client_rpc_types>;

/// Conditional request: this endpoints allows you to invoke a request dependent on the storage
/// server and/or current hardfork version.
///
/// This endpoint takes a dict parameter containing three keys:
///
/// - An `"if"` key contains a dict of conditions to check; this dict has keys:
///   - `"hf_at_least"` -- contains a two-element list of hardfork/softfork revisions, e.g. [19,1].
///     The "yes" endpoint will be invoked if this is true.
///   - `"v_at_least"` -- contains a three-element list of the storage server major/minor/patch
///     versions, e.g. [2,3,0].  The "yes" endpoint will be invoked if this is true.
///   - `"height_at_least"` -- contains a blockchain height (integer); the "yes" branch will be
///     executed if the current blockchain height is at least the given value.
///   - `"hf_before"`, `"hf_before"`, `"height_before"` -- negations of the above "..._at_least"
///     conditions.  e.g. `"hf_at_least": [19,1]` and `"hf_before": [19,1]` follow the opposite
///     branches.
///
///   If more than one key is specified then all given keys must be satisfied to pass the condition.
///   (That is: conditions are "and"ed together).
///
/// - A `"then"` key contains a single request to invoke if the condition is satisfied.  The request
///   itself is specified as a dict containing "method" and "params" keys containing the endpoint to
///   invoke and the parameters to pass to the request.  The given request is permitted to be
///   a nested "ifelse" or a "batch"/"sequence".  Note, however, that batch/sequence requests may
///   not contain "ifelse" requests.
///
/// - An `"else"` key contains a single request to invoke if the condition is *not* satisfied.
///   Parameters are the same as `"then"`.
///
/// `"if"` is always required, and at least one of "then" and "else" is required: if one or the
/// other is omitted then no action is performed if that branch would be followed.
///
/// This endpoint returns a dict containing keys:
/// - "hf" -- the current hardfork version (e.g. [19,1])
/// - "v" -- the running storage server version (e.g. [2,3,0])
/// - "height" -- the current blockchain height (e.g. 1234567)
/// - "condition" -- true or false indicating the logical result of the `"if"` condition.
/// - "result" -- a dict containing the result of the logical branch ("then" or "else") that was
///   followed.  This dict has two keys:
///   - "code" -- the numeric response code (e.g. 200 for a typical success)
///   - "body" -- the response value (usually a dict).
///   If the branch followed was omitted from the request (e.g. the condition failed and only a
///   "then" branch was given) then this "result" key is omitted entirely.
///
/// Example:
///
/// Suppose HF 19.2 introduces some fancy new command "abcd" but earlier versions require executing
/// a pair of commands "ab" and "cd" to get the same effect:
///
/// Request:
///
///     {
///       "if": { "hf_at_least": [19,2] },
///       "then": { "method": "abcd", "params": { "z": 1 } },
///       "else": {
///         "method": "batch",
///         "params": {
///           "requests": [
///             {"method": "ab", "params": {"z": 1}},
///             {"method": "cd", "params": {"z": 3}}
///           ]
///         }
///       }
///     }
///
/// If the 19.2 hf is active then the response would be:
///
///     {
///       "hf": [19,2],
///       "v": [2,3,1],
///       "height": 1234567,
///       "condition": true,
///       "result": { "code": 200, "body": {"z_plus_4": 5}}
///     }
///
/// Response from some blockchain height before hf 19.2:
///
///     {
///       "hf": [19,1],
///       "v": [2,3,1],
///       "height": 1230000,
///       "condition": false,
///       "result": {
///         "code": 200,
///         "body": [
///           {"code": 200, "body": {"z_plus_2": 3}},
///           {"code": 200, "body": {"z_plus_2": 5}}
///         ]
///       }
///     }
///
struct ifelse : endpoint {
    static constexpr auto names() { return NAMES("ifelse"); }

    std::function<bool(const snode::ServiceNode& snode)> condition;
    // We're effectively using these like an std::optional, but we need pointer indirection because
    // we can potentially self-reference (and can't do that with an optional because we haven't
    // fully defined our own type yet).
    std::unique_ptr<client_request> action_true;
    std::unique_ptr<client_request> action_false;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

}  // namespace oxen::rpc
