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
#include <oxenss/common/subaccount_token.h>
#include <oxenss/common/type_list.h>

namespace oxen::snode {
class ServiceNode;
}

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

/// RPC: common/HTTPS
///
/// All endpoints of the storage server are available via self-signed HTTPS on the server's HTTPS
/// port (see [`get_swarms`](/network#get_swarm)).  Typically these requests are not invoked
/// directly but rather through Onion requests, documented elsewhere.
///
/// Inputs:
///
/// An HTTPS request is always a JSON object, submitted via an onion request.  The body of this
/// request must contain two keys:
///
/// - `"method"` - the name of the endpoint, as in these documentation.  For example, `"store"` to
///   upload a new file.
/// - `"params"` - a json object of request parameters.  This can be an empty object, but is always
///   still required even when empty.
///
/// The various documentation endpoints described in this document list input parameters that go
/// into the `"params"` object of this request body.
///
/// Outputs:
///
/// JSON object.  The keys of this returned object is as described in the pages (including the
/// fields described in [Common](#Common) for most non-error responses).

/// RPC: common/OxenMQ
///
/// All storage servers are accessible via OxenMQ connections using curve encryption, at the
/// server's OxenMQ port, using the service node's X25519 public key for encryption (see
/// [`get_swarms`](/network#get_swarm)).
///
/// The endpoints described in this documentation are accessible at OxenMQ request endpoints
/// prefixed with the `"storage."` category, such as `"storage.retrieve"`.
///
/// Inputs:
///
/// The requests take the parameters (described in these pages) as a dict passed the first argument
/// to the request.  This dictionary may be serialized in two ways:
///
/// - As a bencoded dict, such as using [oxen-encoding](https://github.com/oxen-io/oxen-encoding)'s
///   `bt_dict` and `bt_serialize`.
/// - As a json value.
///
/// *(In contrast with HTTPS requests, this dict contains only the parameters (that would be passed as
/// `"params"` with HTTP), not the outer object with `"method"`/`"params"` keys.)*
///
/// Using bt-encoded values is recommended in such cases as it allows efficient encoding of binary
/// data, while JSON requires inefficient serialization to base64 or hex.  Moreover many of the
/// parameters such as public keys and other binary values *must* be passed as byte strings when
/// using OxenMQ.
///
/// Outputs:
///
/// Returned output is either JSON or a bt-encoded dict, depending on whether the **input** was
/// JSON or bt-encoded.
///
/// Example input:
///
/// OxenMQ request to `storage.info` with data:
/// ```json
/// {}
/// ```
///
/// Example output:
///
/// ```json
/// {
///   "hf": [19,3],
///   "t": 1689982896052,
///   "timestamp": 1689982896052,
///   "version": [2,5,0]
/// }
/// ```
///
/// Example input:
///
/// OxenMQ request to `storage.info` with data:
/// ```
/// de
/// ```
///
/// Example output:
///
/// ```
/// d2:hfli19ei3ee1:ti168998289605e9:timestampi1689982896052e7:versionli2ei5ei0eee
/// ```
///

/// RPC: common/Common
///
/// All endpoints of the storage server include some common fields in most responses; these are
/// documented here rather than in the individual endpoint descriptions.  *(This is not an actual
/// request endpoint)*.
///
/// Inputs: none.
///
/// Outputs:
///
/// - "t" -- this contains the current timestamp (as an integer containing unix epoch milliseconds)
///   of the service node the request was made to.  This is included to help clients who may have
///   inaccurate clocks deal with the needs of some endpoints to have reasonably current clocks for
///   authentication: by using a recent `"t"` value clients can attempt to apply a correction to a
///   wrong local clock so that requests can be successfully authenticated.
///
/// - "hf" -- this is a two-element array containing the current Oxen network version.  The first
///   version signifies the network hardfork (e.g. `19` for Oxen 10.x), while the second contains
///   the currently active network revision (e.g. 3 for Oxen 10.3.x).  This is designed to used by
///   clients to detect when features added at hard forks or network upgrades become available.
///
/// Example input:
///
/// ```json
/// { "method": "info", "params": {} }
/// ```
///
/// Example output:
///
/// ```json
/// {
///    "hf": [19, 3],
///    "t": 1689981385058,
///    "timestamp": 1689981385058,
///    "version": [2, 5, 0]
/// }
/// ```
///
/// (Note that in this output `"timestamp"` and `"version"` are specific to the `"info"` endpoint;
/// two separate timestamp fields are included for historical, backwards-compatibility reasons).
///

/// RPC: recursive/Recursive
///
/// *(This is not an endpoint, but rather a description of how the responses of recursive requests to
/// swarm members are collected).*
///
/// Recursive requests are those that need to be broadcast through the swarm, such as storing a
/// message, updating expiries, or revoking a subaccount.  It does not include read-only endpoints
/// such as `retrieve` or `get_swarm`.
///
/// When such a request is received by a swarm member, it is broadcast by that service node to the
/// rest of the swarm members and, upon response or timeout of all members, the result is collected
/// into a single response to return to the user.
///
/// Inputs:
///
/// There are no additional inputs required for recursive requests; the parameters of the request
/// are automatically broadcast to the other swarm members.
///
/// Outputs:
///
/// Upon success, the node that received the original request collect the responses of all swarm
/// members (including its own response) into a dict in "swarm" field of the response.  Each key of
/// this dict is the public key of the service node that produced the response and each value is
/// that service node's response.  Such responses generally include an endpoint-specific
/// `"signature"` field signed by the service node to prevent tampering with the response.
///
/// (The original snode also puts its response values in the top-level, for backwards compatibility
/// with older clients, but it is recommended that the values inside `"swarm"` be used instead).
///
/// Upon failure to receive a sucessful response from another swarm member the original service node
/// will set that service node's value to a dict containing a `"failed": true` key, plus one or more
/// of the following keys:
///
/// - `"timeout": true` if the intra-swarm request timed out
/// - `"code": X` if the intra-swarm request returned numeric error code `X`.
/// - `"reason": "..."` if the swarm member returned an error reason string
/// - `"bad_peer_response": true` if the peer returned an unparseable response
/// - `"query_failure": true` if the remote peer's database failed to perform the query for some
///   reason.
///
/// Example input:
///
/// ```json
/// {
///   "method": "store",
///   "params": {
///     "pubkey": "0557460f9eceb9ce67e74348ed248656a82b7bd42d540273221d0d5154655c4410",
///     "pubkey_ed25519": "83cd4ba7e1f977c97d27b3eff86652a3cd6c6ae567ad9089a7e51994083acc28",
///     "namespace": 123
///     "ttl": 1209600000,
///     "data": "aGVsbG8gd29ybGQK",
///     "timestamp": 1689975701626,
///     "signature": "fI2MN6nxJmgwVUCBrHLhZb7DldcxZKTRlnRi8kaTbjMJ04LaCt0YtdMNPZB+ZCYrAAUy6LzKaRYyNqekb+/8DA",
///   }
/// }
/// ```
///
/// Example output:
///
/// ```json
/// {
///   "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///   "hf": [ 19, 3 ],
///   "swarm": {
///     "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "vJf2CLl2jd9EzasoHsmTcgFmYdVNgrjFV+lUMFrJQSrXgtgjKT4y1uRafxifaM2ncTB7q9cKOClzu152lBhmBw=="
///     },
///     "decaf07a5acbf52d36b9105a7179bc3ad09ebb5020ca6241f54445cff9590f93": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "IxKDnMOSgcJz59DZwe0DN4PEEmlCVQOvaxmVGH2cnOQYXw2x6VAJm9PRiqP87WcTupOMuA8nquvZF0q6T+JbBw=="
///     },
///     "decaf08ad1f68cae3ffbc25276beb7ddb47155ff61c9abc16e58912f3a334a1c": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "f7W90Ru0GLAV555yfnTbNCA3iE4CSs+HVKU47Yo6ps3hNbI97te3l83Fc6iIm+BFXcD2EN+DPh5veWM3uCPRCw==",
///       "t": 1689976277034
///     },
///     "decaf09c9bdf36b8ab1311fd08d1f72b9a08531fd2fd1dbc392e0d3a39616c14": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "1q9jLdEX+Wfi+e+UruKc17et9vESdL5AVDGIqkR7Jk7iGOZABbZ7cmwwp/Z5wZI/XvXznXQjWBoelNGl3MbTCw=="
///     },
///     "decaf10b793034846d75e7c47c0779be782dda63cc9090701b2b5bc423461319": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "Oawdgvhcd3CbOM87LKcGR7m6mPuNszNA+BVKFQDjdWWwtpVn9emn0GupEsA7KhDQYpw1epuM9KxL8RyabPctCA=="
///     },
///     "decaf131572d20fe7b0cb07a8a4e56611818d22235bcf0c00dc1d0443dfdd8b2": {
///       "failed": true,
///       "timeout": true
///     },
///     "decaf16be0059bd818d6203139bc322446baa44195db5cafd0ef6b0ee502eae9": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "gGAUoRKJsKFCl39hLGlIHZiuVqyJ3e44zPygviRaIEODHtKN5vfAn0oG2NW7AzRw0ak/7bK+IXldSlM1M2sBDg=="
///     },
///     "decaf19ed14923f378960962fea11606bad4ebbb93d26e5444cabe52bf9aaa01": {
///       "hash": "t8Nm92edAR8GiMDMGWtcsqA38Li5cZssUVth6O5T4QE",
///       "signature": "sl6mwi1w/os6+GdOxhcxYNIVwpnogM9N0SMeoq4tzDHAFvf5g9yywYnZM3ln0lFCKhIdcSolsmSi+8ZTuvq+Cw=="
///     }
///   },
///   "t": 1689976277034
/// }
///
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

/// RPC: subaccounts/Authentication
///
/// *(This is not actually an endpoint but rather a description of how delegated subaccounts can be
/// used with various other endpoints to authorized another public key to access a storage
/// account.)*
///
/// # Overview
///
/// Subaccount authentication allows an account owner to delegate another public key to interact
/// with a storage account by creating a subaccount tag and a signature of this tag.  When provided
/// this instructs the storage server that it should use the given tag for authentication rather
/// then main account public key.
///
/// In order to use an subaccount for authentication, the subaccount user provides the subaccount
/// tag and signature validating the subaccount as part of the request and then signs the request
/// using the subaccount public key.
///
/// # Details
///
/// A subaccount token is a 36-byte string consisting of:
/// - the network prefix byte, such as `05` for a Session ID.  This is typically the same prefix as
///   the one on the account.
/// - one byte containing permission flags controlling which types of request this subaccount is
///   authorized to access.  Currently supported bit flags are:
///   - Read: the subaccount may retrieve messages and view message expiries, but may not insert,
///     delete, or update message expiries.
///   - Write: the subaccount may insert new messages and extend expiries of existing messages, but
///     may not delete or shorten message expiries.
///   - Delete: the subaccount may delete existing messages and shorten expiries of existing
///     messages.
///   - AnyPrefix: this flag allows a single subaccount to access all accounts regardless of prefix
///     (so, for example, a subaccount for `03{PUBKEY}` with this flag would also have those
///     permissions in 05{PUBKEY}, ee{PUBKEY}, etc.).  Normally, without this flag present, the
///     subaccount is only permitted access within the account with the same prefix.
/// - two reserved bytes (for future use)
/// - An Ed25519 public key (32 bytes) with which the request must be signed instead of the main
///   account's Ed25519 signature.  This can be a bare Ed25519 pubkey, but for privacy it is
///   recommended to use a blinded Ed25519 pubkey instead.
///
/// A `subaccount` tag is paired with a `subaccount_sig` value which is an Ed25519 signature of the
/// subaccount tag, signed by the owner of the account.
///
/// # Subaccount creation example
///
/// An example of granting subaccount access is as followed:
///
/// 1. The owner of account A, with pubkey
///    080123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, wishes to grant account B
///    access to retrieve messages (but not add or modify messages) from the account.
/// 2. The owner constructs a subaccount tag:
///    - 0x08 network prefix
///    - 0x01 for the read permission
///    - 0x00, 0x00 padding/future use bytes
///    - ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100, the blinded version of
///      B's Ed25519 public key.
///      - Any blinding mechanism, or no blinding mechanism at all, can be used, but the owner and B
///        must both know what the mechanism is.  A suggested mechanism is to computed the blinded
///        id `Z` via:
///        - `k = H(A.pubkey || B.pubkey) mod L`
///        - `Z = kB`
///      - When `B` is a session ID blinding is slightly more complicated by Session's historic use
///        of X25519 pubkeys; in this case it is suggested that `z = k|B'|` instead, where `B'` is
///        the Ed25519 associated with the X25519 key, whose absolute value (but not sign) can be
///        derived from the X25519 key.
///      - Another alternative, particularly when `B` does not have a useful public key, is for the
///        account owner to generate a new random Ed25519 keypair and provide the seed to `B`.
///        (This has various disadvantages, such as needing to transmit a private key, and so is not
///        recommended when generation of a blinding ID is feasible).
/// 3. The owner signs the subaccount tag using the account's private key, obtaining signature
///    (expressed in base64) of
///    `wBqJnNmVfr9ZetKZ2hbbgd+5ylVd3nD2uUD6oIdZHKLkBJlWJrGmzVb+iTTn6V3V7iLoy7R3Ac737kGSQdIqzA`.
/// 4. The owner sends the subaccount tag and the authorizing signature to B.
///     - Note: When a known blinding mechanism is in use, it is possible to only transmit the flags
///       instead of the whole tag if space is at a premium.
/// 5. B receives the subaccount tag and signature, optionally verifies that the blinded pubkey is
///    what it expects, and stores these for future use accessing the acccount.
///
/// # Subaccount access example
///
/// To access the account using this subaccount, B makes an ordinary storage server request to the
/// account, but instead of signing as the account owner's signature (which is impossible for B), B
/// signs using the blinded private key associated with the blinded pubkey in the subaccount tag.
///
/// B then provides the includes the `signature`, `subaccount`, and `subaccount_sig` fields in the
/// request:
///
/// ```json
/// {
///     "method": "retrieve",
///     "params": {
///         "pubkey": "080123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
///         "namespace": 42,
///         "last_hash": "eW91J2xsIG5ldmVyIGd1ZXNzIHdoYXQgSSBoYXNoZWQ",
///         "max_count": -1,
///         "timestamp": 1689972350584,
///         "subaccount": "08010000ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
///         "subaccount_sig": "wBqJnNmVfr9ZetKZ2hbbgd+5ylVd3nD2uUD6oIdZHKLkBJlWJrGmzVb+iTTn6V3V7iLoy7R3Ac737kGSQdIqzA",
///         "signature": "iYe2SmpRs5k+s6nXX8LCpGPLzpgiZndnkSBVLO3HtAL+Kn07ls+OgW6MYaOrH8P4YbAqocIrf23h9nt6ncgtNQ"
///     }
/// }
/// ```
/// where the only difference between this and a request by the account owner are the additional
/// subaccount keys, and that `signature` is produced from the delegated subaccount keys rather than
/// the account owner.
///
/// Inputs:
///
/// For subaccount-supporting endpoints two additions parameters are used for subaccount
/// authentication:
///
/// - `subaccount` is the subaccount tag created by the account owner granting another pubkey
///   permission to access this account.  See above.
/// - `subaccount_sig` is the owner-produced signature of `subaccount` granting the key in
///   `subaccount` permissions to access this account.
///
/// Outputs:
///
/// Using a subaccount does not affect the return value of subaccount-enabled endpoints.


/// RPC: storage/store
///
/// Stores data in this service node and forwards it to the rest of the storage swarm.
///
/// Inputs:
/// - `pubkey` (required) contains the pubkey of the recipient, encoded in hex.  Deprecated name for
///   this `pubKey` can be used, but is deprecated and should be migrated to the lower-case name.
///
/// - `timestamp` (required) the timestamp of the message in unix epoch milliseconds, passed as an
///   integer.  Timestamp may not be in the future (though a few seconds tolerance is permitted).
///   For backwards compatibility may be passed as a stringified integer.
///
/// - `ttl` (required, unless expiry given) the message's lifetime, in milliseconds, passed as a
///   string or stringified integer, relative to the timestamp.  Timestamp+ttl must not be in the
///   past.  For backwards compatibility may be passed as a stringified integer, but this behaviour
///   is deprecated.
///
/// - `expiry` (required, unless ttl given) the message's expiry time as a unix epoch milliseconds
///   timestamp.  (Unlike `ttl`, this cannot be passed as a stringified integer).
///
/// - `data` (required) the message data, encoded in base64 (for json requests).  Max data size is
///   76800 bytes (== 102400 in b64 encoding).  For bt-encoded OMQ RPC requests the value is bytes.
///
/// - `namespace` (optional) a non-zero integer namespace (from -32768 to 32767) in which to store
///   this message.  Messages in different namespaces are treated as separate storage boxes from
///   untagged messages.
///
///   Different IDs have different storage properties:
///   - namespaces divisible by 10 (e.g. 0, 60, -30) allow unauthenticated submission: that is,
///     anyone may deposit messages into them without authentication.  Authentication is required
///     for retrieval (and all other operations).
///   - namespaces -30 through 30 are reserved for current and future Session message storage.
///     Currently in use or planned for use are:
///     - `0` (public messages, i.e. DMs)
///     - `-10` (legacy closed groups)
///     - `2` through `5` are used for encrypted libsession-util client config data (profile
///       settings, contacts, conversations, and groups, respectively).
///   - non-divisible-by-10 namespaces require authentication for all operations, including storage.
///
///   Omitting the namespace is equivalent to specifying the 0 namespace.
///
/// - `subaccount` (optional) if provided this is a 36-byte subaccount token.  See below for a
///   description of how subaccount authentication works.
///
/// - `subaccount_sig` (optional) the account owner's signature validating the `subaccount` value.
///   See below.
///
/// # Authentication
///
/// Authentication for a storage request is required only when storing to a namespace not divisible
/// by 10, and must match the pubkey of the storage address (or a delegated subaccount).  If
/// provided then the request will be denied if the signature does not match.  Should not be
/// provided when depositing a message in a public receiving (i.e. divisible by 10) namespace.
///
/// - signature -- Ed25519 signature of ("store" || namespace || sig_timestamp), where namespace and
///   sig_timestamp are the base10 expression of the namespace and sig_timestamp values.  Must be
///   base64 encoded for json requests; binary for bt-encoded OMQ requests.  For non-05 type pubkeys
///   (i.e. non session ids) the signature will be verified using `pubkey`.  For 05 pubkeys, see the
///   following option.  This signature is produced by the private key associated with the account,
///   unless using the `subaccount`/`subaccount_sig` parameters.
///
/// - pubkey_ed25519 if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from *this* given ed25519 pubkey (which must be
///   64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix) for the signature to be
///   accepted.
///
/// - sig_timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
///   epoch, used in the authentication signature.  Must be within ±60s of the current time.  (For
///   clients it is recommended to retrieve a timestamp via `info` first, to avoid client time sync
///   issues).  If omitted, `timestamp` is used instead; it is recommended to include this value
///   separately, particularly if a delay between message construction and message submission is
///   possible.
///
/// Outputs:
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - "hash": the hash of the stored message; will be an unpadded base64-encode blake2b hash of
///       `(PUBKEY || NAMESPACE || DATA)`, where `PUBKEY` is in bytes (not hex!); `DATA` is in bytes
///       (not base64); and `NAMESPACE` is empty for namespace 0, and otherwise is the decimal
///       representation of the namespace index.
///     - `"signature"`: signature of the returned "hash" value (i.e. not in decoded bytes).
///       Returned encoded in base64 for JSON requests, raw bytes for bt-encoded OMQ requests.
///     - `"already"`: will be true if a message with this hash was already stored (note that the
///       hash is still included and signed even if this occurs).
///
struct store final : recursive {
    static constexpr auto names() { return NAMES("store"); }

    /// Maximum `data` size in bytes (max acceptable b64 size will be 4/3 of this).
    inline static constexpr size_t MAX_MESSAGE_BODY = 76'800;

    user_pubkey pubkey;
    std::optional<signed_subaccount_token> subaccount;
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

/// RPC: storage/retrieve
///
/// Retrieves stored data from this storage server.
///
/// Inputs:
/// - `pubkey` (required) the hex-encoded pubkey who is retrieving messages. For backwards
///   compatibility, this can also be specified as `pubKey`
///
/// - `namespace` (optional) the integral message namespace from which to retrieve messages.  Each
///   namespace forms an independent message storage for the same address.  When specified,
///   authentication *must* be provided.  Omitting the namespace is equivalent to specifying a
///   namespace of 0.
///
/// - `last_hash` (optional) retrieve messages stored by this storage server since `last_hash` was
///   stored.  The deprecated name `lastHash` can also be used, but should be migrated to use the
///   `last_hash` name instead.  An empty string (or null) is treated as an omitted value.
///
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
///   Alternatively, if some are expected to be larger than others, you could use different
///   fractions that add up to $\leq 1$.  For example, -2 on a large mailbox (for 1/2 the limit) and
///   -10 on five smaller mailboxes so that that maximum returned data is $1/2 + 5(1/10) = 1$.
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
/// # Authentication parameters
///
/// Required for all namespaces *except* namespace -10 (used for legacy closed groups).
///
/// - `timestamp` -- the timestamp at which this request was initiated, in milliseconds since unix
///
/// - `signature` -- Ed25519 signature of ("retrieve" || namespace || timestamp) (if using a non-0
///   namespace), or ("retrieve" || timestamp) when fetching from the default namespace.  Both
///   namespace and timestamp are the base10 expressions of the relevant values.  Must be base64
///   encoded for json requests; binary for bt-encoded OMQ requests.
///
/// - `pubkey_ed25519` if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
///
/// - `subaccount`/`subaccount_sig` (optional) see description in [subaccount
///   authentication](/subaccounts#Authentication).  Only subaccount tokens with the `read` flag set
///   may invoke this method.
///
/// Outputs:
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

    user_pubkey pubkey;
    std::optional<signed_subaccount_token> subaccount;
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

/// RPC: general/info
///
/// Retrieves status information about this storage server.
///
/// Inputs: none.
///
/// Outputs:
/// - `version` the version of this storage server as a 3-element array, e.g. [2,1,1]
/// - `timestamp` the current time (in milliseconds since unix epoch); clients are recommended to
///   use this rather than local time, especially when submitting delete requests.
///
struct info final : no_args {
    static constexpr auto names() { return NAMES("info"); }
};

/// RPC: storage/delete
///
/// Deletes specific stored messages and broadcasts the delete request to all other swarm
/// members.
///
/// Inputs:
///
/// - `pubkey` -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an X25519 pubkey derived from this given Ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - `messages` -- array of message hash strings (as provided by the storage server) to delete.
///   Message IDs can be from any message namespace(s).
/// - `required` -- if provided and set to true then require that at least one given message is
///   deleted from at least one swarm member for a 200 response; otherwise return a 404.  When this
///   field is omitted (or false) the response will be a 200 OK even if none of the messages
///   existed.
/// - `signature` -- Ed25519 signature of ("delete" || messages...); this signs the value constructed
///   by concatenating "delete" and all `messages` values, using `pubkey` to sign.  Must be base64
///   encoded for json requests; binary for bt-encoded OMQ requests.
/// - `subaccount`/`subaccount_sig` (optional) see description in [subaccount
///   authentication](/subaccounts#Authentication).  Only subaccounts with the read bit set in the
///   subaccount token may invoke this method.
///
/// Outputs:
///
/// - "swarm" dict of [recursive swarm results](/recursive#Recursive) containing:
///     - `"deleted"`: list of hashes of messages that were found and deleted, sorted by ascii value
///     - `"signature"`: signature of:
///             ( PUBKEY_HEX || RMSG[0] || ... || RMSG[N] || DMSG[0] || ... || DMSG[M] )
///       where `RMSG` are the requested deletion hashes and `DMSG` are the actual deletion hashes (note
///       that `DMSG...` and `RMSG...` will not necessarily be in the same order or of the same length).
///       The signature uses the node's ed25519 pubkey.
struct delete_msgs final : recursive {
    static constexpr auto names() { return NAMES("delete"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    std::vector<std::string> messages;
    std::array<unsigned char, 64> signature;
    bool required = false;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// RPC: subaccounts/revoke_subaccount
///
/// Revokes a subaccount.
///
/// This endpoint adds a subaccount tag to the storage server revocation list, which prevents that
/// subaccount tag from being used for authentication.
///
/// Note, however, that this revocation list is a "best effort" primarily intended to shield group
/// metadata; it is *not* intended as a robust or permanent way to guarantee a subaccount will never
/// have future access.  Rather it is expected that applications take care of that by using rotating
/// encryption keys for the content within a shared mailbox; when combined with such key rotation,
/// the revocation list allows prevent a removed user from observing metadata (such as number of
/// messages received), while the key rotation itself is what provides security against reading such
/// messages.
///
/// Inputs:
///
/// - `pubkey` -- the pubkey of the account where the revocation is to be added, in hex (66) or
///   bytes (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - `revoke` -- the subaccount token which is to be added to the revocation list; see [subaccount
///   authentication](/subaccounts#Authentication) for details of the subaccount tag format.
///   Specified in hex or base64 (for JSON), or bytes (for bt-encoded OMQ).
/// - `signature` -- Ed25519 signature of $(\texttt{"revoke_subaccount"} || subaccount)$, where
///   $subaccount$ is in bytes.  Must be base64 encoded for json requests; binary for bt-encoded OMQ
///   requests.
///
/// Outputs:
///
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - "signature": signature of `( PUBKEY_HEX || SUBACCOUNT_TAG_BYTES )`
///       where `SUBACCOUNT_TAG_BYTES` is the requested subaccount tag for revocation
struct revoke_subaccount final : recursive {
    static constexpr auto names() { return NAMES("revoke_subaccount"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    subaccount_token revoke;
    std::array<unsigned char, 64> signature;

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

/// RPC: storage/delete_all
///
/// Deletes all messages owned by the given pubkey on this SN and broadcasts the delete request
/// to all other swarm members.
///
/// Inputs:
///
/// - `pubkey` -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey` will
///   be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must be 64
///   hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also convert
///   to the given `pubkey` value (without the `05` prefix).
/// - `subaccount`/`subaccount_sig` - see `store` for details.  Only subaccounts with the `delete`
///   bit set in the token may invoke this endpoint.
/// - `namespace` -- (optional) the message namespace from which to delete messages.  This is either
///   an integer to delete messages from a specific namespace, or the string "all" to delete all
///   messages from all namespaces.  If omitted, messages are deleted from the default namespace
///   only (namespace 0).
/// - `timestamp` -- the timestamp at which this request was initiated, in milliseconds since unix
///   epoch.  Must be within ±60s of the current time.  (For clients it is recommended to retrieve a
///   timestamp via `info` first, to avoid client time sync issues).
/// - `signature` -- an Ed25519 signature of ( "delete_all" || namespace || timestamp ), where
///   `namespace` is the empty string for the default namespace (whether explicitly specified or
///   not), and otherwise the stringified version of the namespace parameter (i.e. "99" or "-42" or
///   "all").  The signature must be signed by the ed25519 pubkey in `pubkey` (omitting the leading
///   prefix).  Must be base64 encoded for json requests; binary for bt-encoded OMQ requests.
///
/// Outputs:
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - `"deleted"`: if deleting from a single namespace this is a list of hashes of deleted
///       messages from the namespace, sorted by ascii value.  If deleting from all namespaces this
///       is a dict of `{ "namespace": [sorted list of hashes], ... }`
///     - `"signature"`: signature of:
///           ( PUBKEY_HEX || TIMESTAMP || DELETEDHASH[0] || ... || DELETEDHASH[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace delete the
///       `DELETEDHASH` values are totally ordered (i.e. among all the hashes deleted regardless of
///       namespace)
struct delete_all final : recursive {
    static constexpr auto names() { return NAMES("delete_all"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point timestamp;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// RPC: storage/delete_before
///
/// Deletes all stored messages with a timestamp earlier than the specified value and broadcasts
/// the delete request to all other swarm members.
///
/// Inputs:
/// - `pubkey` -- the pubkey whose messages shall be deleted, in hex (66) or bytes (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey`
///   will be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must
///   be 64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix).
/// - `subaccount`/`subaccount_sig` - see `store` for details.  Only subaccounts with the `delete`
///   bit set in the token may invoke this endpoint.
/// - `namespace` -- (optional) the message namespace from which to delete messages.  This is either
///   an integer to delete messages from a specific namespace, or the string "all" to delete
///   messages from all namespaces.  If omitted, messages are deleted from the default namespace
///   only (namespace 0).
/// - `before` -- the timestamp (in milliseconds since unix epoch) for deletion; all stored messages
///   with timestamps <= this value will be deleted.  Should be <= now, but tolerance acceptance
///   allows it to be <= 60s from now.
/// - `signature` -- Ed25519 signature of `("delete_before" || namespace || before)`, signed by
///   `pubkey`.  Must be base64 encoded (json) or bytes (bt-encoded OMQ).  `namespace` is the
///   stringified version of the given non-default namespace parameter (i.e. `"-42"` or `"all"`), or
///   the empty string for the default namespace (whether explicitly given or not).
///
/// Outputs:
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - `"deleted"`: if deleting from a single namespace this is a list of hashes of deleted
///       messages from the namespace, sorted by ascii value.  If deleting from all namespaces this
///       is a dict of `{ "namespace": [sorted list of hashes], ...}`.
///     - `"signature"`: signature of
///           ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace delete the
///       `DELETEDHASH` values are totally ordered (i.e. among all the hashes deleted regardless of
///       namespace)
struct delete_before final : recursive {
    static constexpr auto names() { return NAMES("delete_before"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point before;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// RPC: storage/expire_all
///
/// Updates (shortens) the expiry of all stored messages, and broadcasts the update request to all
/// other swarm members.  Note that this will not extend existing expiries, it will only shorten the
/// expiry of any messages that have expiries after the requested value.  (To extend expiries of one
/// or more individual messages use the `expire` endpoint).
///
/// Inputs:
/// - `pubkey` -- the pubkey whose messages shall have their expiries reduced, in hex (66) or bytes
///   (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey`
///   will be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must
///   be 64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix).
/// - `subaccount`/`subaccount_sig` - see `store` for details.  Only subaccounts with the `delete`
///   bit set in the token may invoke this endpoint.
/// - `namespace` -- (optional) the message namespace from which to change message expiries.  This is
///   either an integer to expire messages from a specific namespace, or the string "all" to update
///   messages in all namespaces.  If omitted, the update applies only to messages from the default
///   namespace (namespace 0).
/// - `expiry` -- the new expiry timestamp (milliseconds since unix epoch).  Should be >= now, but
///   tolerance acceptance allows >= 60s ago.
/// - `signature` -- signature of ("expire_all" || namespace || expiry), signed by `pubkey`.  Must be
///   base64 encoded (json) or bytes (bt-encoded OMQ).  namespace should be the stringified
///   namespace for non-default namespace expiries (i.e. "42", "-99", "all"), or an empty string for
///   the default namespace (whether or not explicitly provided).
///
/// Outputs:
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - `"updated"`:
///         - if expiring from a single namespace then this is a list of (ascii-sorted) hashes that
///           had their expiries updated to `expiry`; messages that did not exist or that already
///           had an expiry <= the given expiry are not included.
///         - otherwise (i.e. namespace="all") this is a dict of `{ namespace => [sorted hashes] }`
///           pairs of updated-expiry message hashes.
///     - `"signature"`: signature of
///           ( PUBKEY_HEX || EXPIRY || UPDATED[0] || ... || UPDATED[N] )
///       signed by the node's ed25519 pubkey.  When doing a multi-namespace expiry update the
///       `UPDATED` values are totally ordered (i.e. among all the messages updated regardless of
///       namespace)
struct expire_all final : recursive {
    static constexpr auto names() { return NAMES("expire_all"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    namespace_var msg_namespace;
    std::chrono::system_clock::time_point expiry;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// RPC: storage/expire_msgs
///
/// Updates (shortens or extends) the expiry of one or more stored messages and broadcasts the
/// update request to all other swarm members.
///
/// Inputs:
/// - `pubkey` -- the pubkey whose messages shall have their expiries reduced, in hex (66) or bytes
///   (33)
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey`
///   will be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must
///   be 64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix).
/// - `subaccount`/`subaccount_sig` - see `store` for details.  Subaccounts must have the `write`
///   bit set to invoke this endpoint at all, but also require the `delete` bit to shorten any
///   expiries.  (That is: with only the write bit set on a subaccount this method will only extend
///   expiries, as if `"extend": true` had been specified).
/// - `messages` -- array of message hash strings (as provided by the storage server) to update.
///   Messages can be from any namespace(s).
/// - `expiry` -- the new expiry timestamp (milliseconds since unix epoch).  Must be >= 60s ago.
///   The new expiry can be anywhere from current time up to the maximum TTL (30 days) from now;
///   specifying a later timestamp will be truncated to the maximum.
/// - `shorten` -- if provided and set to true then the expiry is only shortened, but not extended.
///   If the expiry of a given message is already at or before the given `expiry` timestamp then the
///   expiry of that message will not be changed.
/// - `extend` -- if provided and set to true then the expiry is only extended, but not shortened.
///   If the expiry of a given message is already at or beyond the given `expiry` timestamp then its
///   expiry will not be changed.  This option is mutually exclusive of "shorten".
/// - `signature` -- Ed25519 signature of:
///       ("expire" || ShortenOrExtend || expiry || messages[0] || ... || messages[N])
///   where `expiry` is the expiry timestamp expressed as a string.  `ShortenOrExtend` is string
///   "shorten" if the shorten option is given (and true), "extend" if `extend` is true, and empty
///   otherwise. The signature must be base64 encoded (json) or bytes (bt).
///
/// Outputs:
///
/// - `"swarm"` dict of [recursive swarm results](/recursive#Recursive) containing:
///     - `"updated"`: ascii-sorted list of hashes that had their expiries changed (messages that
///       were not found, and messages excluded by the shorten/extend options, are not included).
///     - `"unchanged"`: dict of hashes to current expiries of hashes that were found, but did not
///       get updated expiries due a given "shorten"/"extend" constraint in the request.  This field
///       is only included when the "shorten" or "extend" parameter is explicitly given.
///     - `"expiry"`: the expiry timestamp that was applied (which might be different from the
///       request expiry, e.g. if the requested value exceeded the permitted TTL).
///     - `"signature"`: signature of:
///             ( PUBKEY_HEX || EXPIRY || RMSGs... || UMSGs... || CMSG_EXPs... )
///       where `RMSG`s are the requested expiry hashes, `UMSG`s are the actual updated hashes, and
///       `CMSG_EXP`s are `(HASH || EXPIRY)` values, ascii-sorted by hash, for the unchanged message
///       hashes included in the `"unchanged"` field.  The signature uses the node's ed25519 pubkey.
struct expire_msgs final : recursive {
    static constexpr auto names() { return NAMES("expire"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    std::vector<std::string> messages;
    std::chrono::system_clock::time_point expiry;
    bool shorten = false;
    bool extend = false;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
    oxenc::bt_value to_bt() const override;
};

/// RPC: storage/get_expiries
///
/// Retrieves the current expiry timestamps of the given messages.
///
/// Inputs:
/// - `pubkey` -- the account
/// - `pubkey_ed25519` -- if provided *and* the pubkey has a type 05 (i.e. Session id) then `pubkey`
///   will be interpreted as an `x25519` pubkey derived from this given ed25519 pubkey (which must
///   be 64 hex characters or 32 bytes).  *This* pubkey should be used for signing, but must also
///   convert to the given `pubkey` value (without the `05` prefix).
/// - `subaccount`/`subaccount_sig` - see `store` for details.  Only subaccounts with the `read` bit
///   set in the token may invoke this endpoint.
/// - `messages` -- array of message hash strings (as provided by the storage server) to update.
///   Messages can be from any namespace(s).  You may pass a single message id of "all" to retrieve
///   the timestamps of all
/// - `timestamp` -- the timestamp at which this request was initiated, in milliseconds since unix;
///   must with ±60s of the current time (as with other signature timestamps, using the server time
///   is recommended).
/// - `signature` -- Ed25519 signature of:
///       ("get_expiries" || timestamp || messages[0] || ... || messages[N])
///   where `timestamp` is expressed as a string (base10).  The signature must be base64 encoded
///   (json) or bytes (bt).
///
///
/// Outputs:
/// - "expiries" sub-dict of messageid => expiry (milliseconds since unix epoch) pairs.  Only
///   message that exist on the server are included.
struct get_expiries final : endpoint {
    static constexpr auto names() { return NAMES("get_expiries"); }

    user_pubkey pubkey;
    std::optional<std::array<unsigned char, 32>> pubkey_ed25519;
    std::optional<signed_subaccount_token> subaccount;
    std::vector<std::string> messages;
    std::chrono::system_clock::time_point sig_ts;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// RPC: general/get_swarm
///
/// Retrieves the swarm information for a given pubkey.  This can be invoked on any active service
/// node and returns information about the proper swarm to go to for a given pubkey.
///
/// Old-names: get_snodes_for_pubkey
///
/// Inputs:
/// - `pubkey` (required) the pubkey to query, in hex (66) or bytes (33).
///
/// Outputs:
///
/// - `"swarm": "swarm_id_hex"` - contains the target swarm ID, encoded as a hex string.  (This ID
///   is a unsigned, 64-bit value and cannot be reliably transported unencoded through JSON).
///
/// - `"snodes": [ ... ]` - an array containing the list of service nodes in the target swarm.  Each
///   element is a dict containing keys:
///   - `"address"` - DEPRECATED. The public key of the service node, base32z-encoded with
///     `".snode"` appended.
///     - It is recommend to ignore this value entirely and instead use whichever of the
///       `"pubkey_*"` keys is appropriate.  In particular this value is misleading because it is
///       *sometimes* the same as the service node's Lokinet `".snode"` address, but not always: the
///       Lokinet address is always based on the `"pubkey_ed25519"` value, while the value returned
///       in this field is the encoded `"pubkey_legacy"` value.
///   - `"ip"` - the IPv4 address of the service node.
///   - `"port"` - DEPRECATED - the HTTPS port of the storage server, but stuffed into a string for
///     unknown historical reasons.  Use `port_https` or `port_omq` instead.
///   - `"port_https"` - the storage server HTTPS port of the service node.
///   - `"port_omq"` - the storage server port where OxenMQ is listening.
///   - `"pubkey_legacy"` - the pubkey of this service node; this is the primary service node pubkey
///     on the Oxen network for service node registrations, but is only used as an identifier
///     outside of Oxen Core itself; instead, for encryption or signing the relevant pubkeys are the
///     "pubkey_ed25519" or "pubkey_x25519" public keys.
///   - `"pubkey_ed25519" - the Ed25519 public key of this service node.  This is the public key the
///     service node uses wherever a signature is required (such as when signing [recursive
///     requests](/recursive)).
///   - `"pubkey_x25519" - this is the X25519 pubkey key of this service node, used for encrypting
///     onion requests and for establishing an encrypted connection to the storage server's OxenMQ
///     port.
///
/// Example input:
///
/// ```json
/// {
///   "method": "get_swarm",
///   "params": {
///     "pubkey": "05abcdeffedcba01234567899876543210abcdeffedcba01234567899876543210"
///   }
/// }
/// ```
///
/// Example output:
///
/// ```json
/// {
///   "hf": [ 19, 3 ],
///   "snodes": [
///     {
///       "address": "55fxys9x58xwnk3gorpwyep47y9knc4c1d15efjwzhybtom7mypy.snode",
///       "ip": "88.99.102.229",
///       "port": "35505",
///       "port_https": 35505,
///       "port_omq": 35405,
///       "pubkey_ed25519": "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a",
///       "pubkey_legacy": "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a",
///       "pubkey_x25519": "ff3a118a72ce7cb87e146b259d7ce739b96bea7ca1ede387a17a185a9fc72379"
///     },
///     {
///       "address": "55fxn93891jqjh58emohktqyzaajyu37gn1ef6pb8wuchs55upiy.snode",
///       "ip": "104.243.43.55",
///       "port": "35517",
///       "port_https": 35517,
///       "port_omq": 35417,
///       "pubkey_ed25519": "decaf17f27fc92e4f36742e1c545c0be30904f3d30a482f9a13d26ce5b7b9b6a",
///       "pubkey_legacy": "decaf17f27fc92e4f36742e1c545c0be30904f3d30a482f9a13d26ce5b7b9b6a",
///       "pubkey_x25519": "15064b5cbe8200ecbc12b02055c342978441825a807c283a1a6ef3505b2ee32c"
///     },
///     {
///       "address": "55fxne4863o4r4ohntbnx1baqupfgmghdw4sas5zbnxso4a9d1oy.snode",
///       "ip": "199.127.60.6",
///       "port": "35512",
///       "port_https": 35512,
///       "port_omq": 35412,
///       "pubkey_ed25519": "decaf12347f661a26a1c144227c83874da532cdc1d356c5b77089f686b1f1ca0",
///       "pubkey_legacy": "decaf12347f661a26a1c144227c83874da532cdc1d356c5b77089f686b1f1ca0",
///       "pubkey_x25519": "3de438d29c151c96eeef0791f638922277f76b6cf847527a7690270862adf810"
///     },
///     {
///       "address": "55fxy4hjmiqxpcupf4gz54y8581dwbrppy6tbsjo11pgku374nxy.snode",
///       "ip": "104.194.11.120",
///       "port": "35506",
///       "port_https": 35506,
///       "port_omq": 35406,
///       "pubkey_ed25519": "decaf06b895d5cf6b26d2e8d7de807d9e43a048d683d10d930949a654f3dd09e",
///       "pubkey_legacy": "decaf06b895d5cf6b26d2e8d7de807d9e43a048d683d10d930949a654f3dd09e",
///       "pubkey_x25519": "3cfbe4c82ef64e57e2b54b037377cc98eba571f7d92a2920e004b76350599d42"
///     },
///     {
///       "address": "55fxyo4r61dfhdx7px4p5zfajw1nkfmtttz51yyc4yif4gfmcgby.snode",
///       "ip": "88.99.102.229",
///       "port": "35504",
///       "port_https": 35504,
///       "port_omq": 35404,
///       "pubkey_ed25519": "decaf04344f4865e0dfd6bf4dddcb84d242515718c6fb9000cd02a5d18ab6182",
///       "pubkey_legacy": "decaf04344f4865e0dfd6bf4dddcb84d242515718c6fb9000cd02a5d18ab6182",
///       "pubkey_x25519": "bad44806896a4648be70c575d207cd8181ff1f46372f6f839209d32f638c8e79"
///     },
///     {
///       "address": "55fxngtbfyfsjxy1tnw6qruzjm64rr96pews7bmg5an39zihnrxo.snode",
///       "ip": "104.194.8.115",
///       "port": "35511",
///       "port_https": 35511,
///       "port_omq": 35411,
///       "pubkey_ed25519": "decaf11a21280b64bc1288a9e712774afda213fe6a296e8566de059fdebc111f",
///       "pubkey_legacy": "decaf11a21280b64bc1288a9e712774afda213fe6a296e8566de059fdebc111f",
///       "pubkey_x25519": "dc4b3f37060c7ce27cb96db992a1ea437c0ee3f0db05ffe44f452c5974e56c6c"
///     },
///     {
///       "address": "55fxdnig4eyeuffkwsw3x37bb7weuby1xtj13ggcwamghctjs9so.snode",
///       "ip": "104.243.40.38",
///       "port": "35518",
///       "port_https": 35518,
///       "port_omq": 35418,
///       "pubkey_ed25519": "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed",
///       "pubkey_legacy": "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed",
///       "pubkey_x25519": "6a1db6f30e5873bfb26e12e1f624427c16f1bc360db5632db01dadefc74ea730"
///     },
///     {
///       "address": "55fxy88kumfmminzw6rs4rerqwiwnx577b1dre5eoefup4t4z99o.snode",
///       "ip": "144.76.164.202",
///       "port": "35501",
///       "port_https": 35501,
///       "port_omq": 35401,
///       "pubkey_ed25519": "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff",
///       "pubkey_legacy": "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff",
///       "pubkey_x25519": "2d16235ed04ea9adf734adb835eca895c7deaaac41b41dcddc02c8e041c8d43e"
///     }
///   ],
///   "swarm": "3fffffffffffffff",
///   "t": 1689979302459
/// }
/// ```
///
struct get_swarm final : endpoint {
    static constexpr auto names() { return NAMES("get_swarm", "get_snodes_for_pubkey"); }

    user_pubkey pubkey;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// RPC: general/oxend_request
///
/// Forwards an RPC request to the this storage server's oxend.
///
/// Inputs:
///
/// - `endpoint` (required) the public oxend endpoint name such as "ons_resolve". Only accepts
///   whitelisted oxend rpc endpoints; currently supported are:
///     - [`get_service_nodes`](https://api.oxen.io/oxend/#/service_node?id=get_service_nodes)
///     - [`ons_resolve`](https://api.oxen.io/oxend/#/ons?id=ons_resolve)
/// - `params` (optional) dict of parameters to forward to oxend.  Can be omitted or null if no
///   parameters should be passed.
///
/// See [oxend RPC](https://api.oxen.io/oxend) documentation (or the
/// oxen-core/src/rpc/core_rpc_server_command_defs.h file) for information on using these oxend rpc
/// endpoints.
///
/// Output:
/// - `"result"` -- contains the JSON as returned by oxend for the request.
///
/// Example input:
///
/// ```json
/// {
///   "method": "oxend_request",
///   "params": {
///     "endpoint": "ons_resolve",
///     "params": {
///       "type": 0,
///       "name_hash": "yB7mbm2q1MaczqNZCYguH+71z5jooEMeXA0sncfni+g="
///     }
///   }
/// }
/// ```
///
/// Example output:
///
/// ```json
/// {
///   "hf": [19, 3],
///   "result": {
///     "encrypted_value": "d9bca6752665f2254ec7522f98aa5f2dfb13c9fa1ad1e39cd3d7a89a0df04719e348da537bc310a53e3b59ca24639b9b42",
///     "nonce": "73e8243f3fadd471be36c6df3d62f863f9bb3a9d1cc696c0"
///   },
///   "t": 1689985591067
/// }
/// ```
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
        revoke_subaccount,
        store,
        retrieve,
        delete_msgs,
        delete_all,
        delete_before,
        expire_msgs,
        expire_all,
        get_expiries,
        get_swarm,
        oxend_request,
        info>;

using client_subrequest = type_list_variant_t<client_rpc_subrequests>;

/// RPC: general/batch
///
/// Batch requests allow a caller to execute a series of sub-requests, collecting and returning the
/// individual responses.  Note that authentication signatures are required for *each* subrequest as
/// described elsewhere in this documentation, not on the outer batch request itself.
///
/// Note that requests may be performed in parallel or out of order; if you require sequential
/// requests (e.g. because a later request in a sequence depends on an earlier request having
/// completed) use [`sequence`](#sequence) instead.
///
/// Inputs:
///
/// This request takes an object containing a single key `"requests"` which contains a list of 1 to
/// 20 elements to invoke up to 20 subrequests.  Each element is a dict containing keys:
///
/// - `"method"` -- the method name, e.g. "retrieve".
/// - `"params"` -- the parameters to pass to the subrequest.
///
/// `"params"` must include any required pubkeys/signatures for the individual subrequest.
///
/// Returned is a dict with key `"results"` containing a list of the same length of the request,
/// which each element contains the subrequest response to the subrequest in the same position, in a
/// dict containing:
///
/// - `"code"` -- the numeric response code (e.g. 200 for a typical success)
/// - `"body"` -- the response value (usually a dict).
///
/// For example, to invoke rpc endpoint `"foo"` with parameters `{"z": 3}` and endpoint `"bar"` with
/// parameters `{"z": 2}` you would invoke the batch endpoint with parameter:
///
/// ```json
///     {"requests": [{"method": "foo", "params": {"z": 3}}, {"method": "bar", "params": {"z": 2}}]}
/// ```
///
/// and would get a reply such as:
///
/// ```json
///     {"results": [{"code": 200, "body": {"z_plus_2": 5}}, {"code": 404, "no such z=2 found!"}]}
/// ```
///
/// Note that, when making the request via HTTP JSON RPC, this is encapsulated inside an outer
/// method/params layer for the `"batch"` request itself, so the full request would look like this:
///
/// ```json
///     {
///       "method": "batch",
///       "params": {
///         "requests": [
///           { "method": "one", "params": {"z": 1} },
///           { "method": "two", "params": {"y": 2} }
///         ]
///       }
///     }
/// ```
///
/// The batch request itself returns a 200 status code if the batch was processed, regardless of the
/// return value of the individual subrequests (i.e. you get a 200 back even if all subrequests
/// returned error codes).  Error statuses are returned only for an error in the batch request
/// itself (e.g. missing method/params arguments, invalid/unparsable subrequests, or too many
/// subrequests).
///
/// Note that batch requests may not recurse (i.e. you cannot invoke the batch endpoint as a batch
/// subrequest).
///
/// Outputs:
/// - `"results"` containing an array of subrequest responses; see details above.
///
struct batch : endpoint {
    static constexpr auto names() { return NAMES("batch"); }

    std::vector<client_subrequest> subreqs;

    void load_from(nlohmann::json params) override;
    void load_from(oxenc::bt_dict_consumer params) override;
};

/// RPC: general/sequence
///
/// Sequences: these works similarly to batch requests (and take the same arguments) but differs in
/// how the subrequests are processed:
///
/// - requests are guaranteed to be processed sequentially; that is, subrequest `n+1` will not be started
/// until subrequest `n` has finished; and
/// - an error in the sequence aborts processing further requests if a subrequest fails (i.e.
///   returns a non-2xx status code).
///
/// For example, if you execute sequence method1, method2, method3 and method2 returns status code
/// 456 then method3 is not executed at all, and the result will contain 2 responses: the successful
/// method1 response, and the method2 failure, but no responses after the failure.
///
/// Inputs:
///
/// See [batch](#batch).
///
/// Outputs:
///
/// See [batch](#batch).
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

/// RPC: general/ifelse
///
/// Conditional request: this endpoints allows you to invoke a request dependent on the storage
/// server and/or current hardfork version.  This is particularly useful to allow clients to opt
/// into new features when talking to a service node when it isn't certain which version of the
/// storage server or hard fork the service node will be on.
///
/// Inputs:
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
/// Outputs:
///
/// - `"hf"` -- the current hardfork version (e.g. [19,3])
/// - `"v"` -- the running storage server version (e.g. [2,3,0])
/// - `"height"` -- the current blockchain height (e.g. 1234567)
/// - `"condition"` -- true or false indicating the logical result of the `"if"` condition.
/// - `"result"` -- a dict containing the result of the logical branch (`"then"` or `"else"`) that
///   was followed.  This dict has two keys:
///   - `"code"` -- the numeric response code (e.g. 200 for a typical success)
///   - `"body"` -- the response value (usually a dict).
///   If the branch followed was omitted from the request (e.g. the condition failed and only a
///   `"then"` branch was given) then this `"result"` key is omitted entirely.
///
/// Example input:
///
/// Suppose HF 19.2 introduces some fancy new command "abcd" but earlier versions require executing
/// a pair of commands "ab" and "cd" to get the same effect:
///
/// ```json
/// {
///   "if": { "hf_at_least": [19,2] },
///   "then": { "method": "abcd", "params": { "z": 1 } },
///   "else": {
///     "method": "batch",
///     "params": {
///       "requests": [
///         {"method": "ab", "params": {"z": 1}},
///         {"method": "cd", "params": {"z": 3}}
///       ]
///     }
///   }
/// }
/// ```
///
/// Example output:
///
/// If the 19.2 hf is active then the response would be:
///
/// ```json
/// {
///   "hf": [19,2],
///   "v": [2,3,1],
///   "height": 1234567,
///   "condition": true,
///   "result": { "code": 200, "body": {"z_plus_4": 5}}
/// }
/// ```
///
/// If invoked before hf 19.2 has taken effect, however, would return:
///
/// ```json
/// {
///   "hf": [19,1],
///   "v": [2,3,1],
///   "height": 1230000,
///   "condition": false,
///   "result": {
///     "code": 200,
///     "body": [
///       {"code": 200, "body": {"z_plus_2": 3}},
///       {"code": 200, "body": {"z_plus_2": 5}}
///     ]
///   }
/// }
/// ```
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
