#pragma once

#include "oxen_common.h"
#include <array>
#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>
#include <oxenmq/bt_serialize.h>

namespace oxen::rpc {

using namespace std::literals;

// Client rpc endpoints, accessible via the HTTPS storage_rpc endpoint, the OMQ "storage.whatever"
// endpoints, and as the final target of an onion request.


/// Thrown when parsing parameters when we encounter missing required fields, invalid value types,
/// etc.  `what()` is designed to be returned to the request initiator.
struct parse_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Common base type decorator of all client rpc endpoint types.
struct endpoint {
    // Loads the rpc request from json.  Throws on error (missing keys, bad values, etc.).
    virtual void load_from(nlohmann::json params) = 0;
    virtual void load_from(oxenmq::bt_dict_consumer params) = 0;

    bool b64 = true; // True if we need to base64-encode values (i.e. for json); false if we can deal with binary (i.e. bt-encoded)

    virtual ~endpoint() = default;
};

// Base type for no-argument endpoints
struct no_args : endpoint {
    void load_from(nlohmann::json) override {}
    void load_from(oxenmq::bt_dict_consumer) override {}
};

// Base type for a "recursive" endpoint: that is, where the request gets forwarded from the initial
// swarm member to all other swarm members.
struct recursive : endpoint {
    // True on the initial client request, false on forwarded requests
    bool recurse;
};

namespace {
  /// Returns a constexpr std::array of string_views from an arbitrary list of string literals
  /// Used to specify RPC names as:
  /// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
  template <size_t... N>
  constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&...names)[N]) {
    static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
    return {std::string_view{names, N-1}...};
  }
}

/// Stores data in this service node and forwards it to the rest of the storage swarm.  Takes keys of:
/// - `pubkey` (required) contains the pubkey of the recipient, encoded in hex.  Can also use the
/// key name `pubKey` for this.
/// - `timestamp` (required) the timestamp of the message in unix epoch milliseconds, passed as an
/// integer.  Timestamp may not be in the future (though a few seconds tolerance is permitted).  For
/// backwards compatibility may be passed as a stringified integer.
/// - `ttl` (required, unless expiry given) the message's lifetime, in milliseconds, passed as a string
/// or stringified integer, relative to the timestamp.  Timestamp+ttl must not be in the past.  For
/// backwards compatibility may be passed as a stringified integer.
/// - `expiry` (required, unless ttl given) the message's expiry time as a unix epoch milliseconds
/// timestamp.  (Unlike the above, this cannot be passed as an integer).
/// - `data` (required) the message data, encoded in base64 (for json requests).  Max data size is
/// 76800 bytes (== 102400 in b64 encoding).  For OMQ RPC requests the value is bytes.
struct store final : endpoint {
    static constexpr auto names() { return NAMES("store"); }

    /// Maximum `data` size in bytes (max acceptable b64 size will be 4/3 of this).
    inline static constexpr size_t MAX_MESSAGE_BODY = 76'800;

    user_pubkey_t pubkey;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry; // computed from timestamp+ttl if ttl was given
    std::string data; // always stored here in bytes

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Retrieves data from this service node. Takes keys of:
/// - `pubkey` (required) the hex-encoded pubkey who is retrieving messages. For backwards
/// compatibility, this can also be specified as `pubKey`
/// - `last_hash` (optional) retrieve messages stored by this storage server since `last_hash` was
/// stored.  Can also be specified as `lastHash`.  An empty string (or null) is treated as an
/// omitted value.
struct retrieve final : endpoint {
    static constexpr auto names() { return NAMES("retrieve"); }

    user_pubkey_t pubkey;
    std::optional<std::string> last_hash;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Retrieves status information about this storage server.  Takes no parameters.
///
/// Returns:
/// - `version` the version of this storage server as a 3-element array, e.g. [2,1,1]
/// - `timestamp` the current time (in milliseconds since unix epoch); clients are recommended to
/// use this rather than local time, especially when submitting delete requests.
///
struct info final : no_args {
    static constexpr auto names() { return NAMES("info"); }
};


/// Deletes specific stored messages and broadcasts the delete request to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted
/// - messages -- array of message hashes (in hex) to delete
/// - signature -- Ed25519 signature of `messages`; this signs the value constructed by
/// concatenating all `messages` values, using `pubkey` to sign.  Must be base64 encoded for json
/// requests; binary for OMQ requests.
struct delete_msgs final : recursive {
    static constexpr auto names() { return NAMES("delete"); }

    user_pubkey_t pubkey;
    std::vector<std::string> messages;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Deletes all messages owned by the given pubkey on this SN and broadcasts the delete request to
/// all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted
/// - timestamp -- the timestamp at which this request was initiated, in milliseconds since unix
/// epoch.  Must be within ±60s of the current time.  (For clients it is recommended to retrieve a
/// timestamp via `info` first, to avoid client time sync issues).
/// - signature -- an Ed25519 signature of the timestamp value (expressed as a string), signed by
/// the ed25519 pubkey in `pubkey` (omitting the leading prefix).  Must be base64 encoded for json
/// requests; binary for OMQ requests.
struct delete_all final : recursive {
    static constexpr auto names() { return NAMES("delete_all"); }

    user_pubkey_t pubkey;
    std::chrono::system_clock::time_point timestamp;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Deletes all stored messages with a timestamp earlier than the specified value and broadcasts the
/// delete request to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall be deleted
/// - before -- the timestamp (in milliseconds since unix epoch) for deletion; all stores messages
/// with timestamps <= this value will be deleted.
/// - signature -- Ed25519 signature of the before value (expressed as a string), signed by
/// `pubkey`.  Must be base64 encoded (json) or bytes (OMQ).
struct delete_before final : recursive {
    static constexpr auto names() { return NAMES("delete_before"); }

    user_pubkey_t pubkey;
    std::chrono::system_clock::time_point before;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Updates (shortens) the expiry of all stored messages, and broadcasts the update request to all
/// other swarm members.  Note that this will not extend existing expiries, it will only shorten the
/// expiry of any messages that have expiries after the requested value.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall have their expiries reduced.
/// - expiry -- the new expiry timestamp (milliseconds since unix epoch).  Must be >= 60s ago.
/// - signature -- signature of the expiry value, expressed as a string, signed by `pubkey`.  Must
/// be base64 encoded (json) or bytes (OMQ).
struct expire_all final : recursive {
    static constexpr auto names() { return NAMES("expire_all"); }

    user_pubkey_t pubkey;
    std::chrono::system_clock::time_point expiry;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};

/// Updates (shortens) the expiry of one or more stored messages and broadcasts the update request
/// to all other swarm members.
///
/// Takes parameters of:
/// - pubkey -- the pubkey whose messages shall have their expiries reduced.
/// - messages -- array of message hashes (in hex) to update
/// - expiry -- the new expiry timestamp (milliseconds since unix epoch).  Must be >= 60s ago.
/// - signature -- Ed25519 signature of `messages[0] || ... || messages[N] || expiry` (where
/// `expiry` is the expiry timestamp expressed as a string).  Must be base64 encoded (json) or bytes
/// (OMQ).
struct expire_msgs final : recursive {
    static constexpr auto names() { return NAMES("expire"); }

    user_pubkey_t pubkey;
    std::vector<std::string> messages;
    std::chrono::system_clock::time_point expiry;
    std::array<unsigned char, 64> signature;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
};



/// Retrieves the swarm information for a given pubkey. Takes keys of:
/// - `pubkey` (required) the pubkey to query
struct get_swarm final : endpoint {
    static constexpr auto names() { return NAMES("get_swarm", "get_snodes_for_pubkey"); }

    user_pubkey_t pubkey;

    void load_from(nlohmann::json params) override;
    void load_from(oxenmq::bt_dict_consumer params) override;
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
    void load_from(oxenmq::bt_dict_consumer params) override;
};


// Type wrapper than contains an arbitrary list of types.
template <typename...> struct type_list {};

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
    info
>;

}
