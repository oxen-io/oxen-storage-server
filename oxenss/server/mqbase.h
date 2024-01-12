#pragma once

#include <chrono>
#include <memory>
#include <variant>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <quic/connection.hpp>
#include <oxenmq/connections.h>
#include <shared_mutex>

#include "../common/namespace.h"
#include "utils.h"

namespace oxenss {

namespace rpc {
    class RequestHandler;
    class RateLimiter;
}  // namespace rpc

struct message;

}  // namespace oxenss

namespace oxenss::server {

// FIXME: with upcoming quic changes the second type here needs to become a ConnRefID (or whatever
// it gets called).
using connection_id = std::variant<oxenmq::ConnectionID, oxen::quic::ConnectionID>;

using namespace std::literals;

struct MonitorData {
    static constexpr auto MONITOR_EXPIRY_TIME = 65min;

    std::chrono::steady_clock::time_point expiry;  // When this notify reg expires
    std::vector<namespace_id> namespaces;          // sorted namespace_ids
    connection_id conn;
    bool want_data;  // true if the subscriber wants msg data

    MonitorData(
            std::vector<namespace_id> namespaces,
            bool data,
            connection_id c,
            std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) :
            expiry{std::chrono::steady_clock::now() + ttl},
            namespaces{std::move(namespaces)},
            conn{c},
            want_data{data} {}

    void reset_expiry(std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) {
        expiry = std::chrono::steady_clock::now() + ttl;
    }
};

/// Base method for common functionality for message-queue request classes, that is, OxenMQ and
/// BTRequestStream.

class MQBase {
  protected:
    rpc::RequestHandler* request_handler_ = nullptr;
    rpc::RateLimiter* rate_limiter_ = nullptr;

    // Attempts to handle the given request, by name.  Returns true if the name was found (in which
    // case the response is handled), false if not found.
    bool handle_client_rpc(
            std::string_view name,
            std::string_view params,
            const std::string& remote_addr,
            std::function<void(http::response_code status, std::string_view body)> reply,
            bool forwarded = false);

    // Subclasses may override this to extend a json or bt response with a status code.  The default
    // returns the given response as-is.  This is primarily aimed at the QUIC implementation which
    // combines status code + body into a list (the OMQ version does not, but rather sends them as
    // two separate frames of the response for errors).
    virtual nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status, nlohmann::json response) const {
        return response;
    }

    // Called to deal with a monitor request; `reply` is used to respond to the request itself (and
    // will be used during, not after, the method call itself); `conn` is the connection ID used to
    // send notifications back on the connection later.  `conn` is used to uniquely identify the
    // connection: if we get a subsequent subscription request from the same `conn`, we replace the
    // old subscription(s) with the new one(s).
    //
    // The `request` body itself can either be a dict, or a list of dicts, to subscribe to one or
    // multiple addresses at once.
    void handle_monitor(
            std::string_view request, std::function<void(std::string)> reply, connection_id conn);

    void update_monitors(std::vector<sub_info>& subs, connection_id conn);

    // Tracks accounts we are monitoring for OMQ push notification messages
    std::unordered_multimap<std::string, MonitorData> monitoring_;
    mutable std::shared_mutex monitoring_mutex_;

  public:
    void get_notifiers(
            message& m, std::vector<connection_id>& to, std::vector<connection_id>& with_data);

    virtual void notify(std::vector<connection_id>&, std::string_view notification) = 0;

  private:
    void handle_monitor_message_single(
            oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<sub_info>& subs);
    void handle_monitor_message_single(
            oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<sub_info>& subs);
};

}  // namespace oxenss::server
