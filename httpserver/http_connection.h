#pragma once

#include <iostream>
#include <map>
#include <memory>

#include "../external/json.hpp"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/format.hpp>

#include "swarm.h"

constexpr auto LOKI_SENDER_SNODE_PUBKEY_HEADER = "X-Loki-Snode-PubKey";
constexpr auto LOKI_SNODE_SIGNATURE_HEADER = "X-Loki-Snode-Signature";

template <typename T>
class ChannelEncryption;

namespace http = boost::beast::http; // from <boost/beast/http.hpp>

using request_t = http::request<http::string_body>;
using response_t = http::response<http::string_body>;

namespace service_node {
namespace storage {
struct Item;
}
} // namespace service_node

using service_node::storage::Item;

namespace loki {
using swarm_callback_t = std::function<void(const all_swarms_t&)>;

struct message_t;

enum class SNodeError { NO_ERROR, ERROR_OTHER, NO_REACH };

struct sn_response_t {
    SNodeError error_code;
    std::shared_ptr<std::string> body;
};

using http_callback_t = std::function<void(sn_response_t)>;

void make_http_request(boost::asio::io_context& ioc, const std::string& ip,
                       uint16_t port, const std::shared_ptr<request_t>& req,
                       http_callback_t&& cb);

void request_swarm_update(boost::asio::io_context& ioc,
                          const swarm_callback_t&& cb);

class HttpClientSession
    : public std::enable_shared_from_this<HttpClientSession> {

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    tcp::socket socket_;
    tcp::endpoint endpoint_;
    http_callback_t callback_;
    boost::asio::steady_timer deadline_timer_;

    boost::beast::flat_buffer buffer_;
    /// NOTE: this needs to be a shared pointer since
    /// it is very common for the same request to be
    /// sent to multiple snodes
    std::shared_ptr<request_t> req_;
    response_t res_;

    bool used_callback_ = false;

    void on_connect();

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void trigger_callback(SNodeError error,
                          std::shared_ptr<std::string>&& body);

  public:
    // Resolver and socket require an io_context
    HttpClientSession(boost::asio::io_context& ioc, const tcp::endpoint& ep,
                      const std::shared_ptr<request_t>& req,
                      http_callback_t&& cb);

    // initiate the client connection
    void start();

    ~HttpClientSession();
};

namespace http_server {

class connection_t : public std::enable_shared_from_this<connection_t> {

    using tcp = boost::asio::ip::tcp;

  private:
    boost::asio::io_context& ioc_;

    // The socket for the currently connected client.
    tcp::socket socket_;

    // The buffer for performing reads.
    boost::beast::flat_buffer buffer_{8192};

    // The request message.
    request_t request_;

    // The response message.
    response_t response_;

    // whether the response should be sent asyncronously,
    // as opposed to directly after connection_t::process_request
    bool delay_response_ = false;

    ServiceNode& service_node_;

    ChannelEncryption<std::string>& channel_cipher_;

    // The timer for putting a deadline on connection processing.
    boost::asio::steady_timer deadline_;

    /// TODO: move these if possible
    std::map<std::string, std::string> header_;

    std::stringstream body_stream_;

    // Note that we are only sending a single message through the
    // notification mechanism. If we somehow accumulated multiple
    // messages before notification event happens (unlikely), the
    // following messages will be delivered with the client's
    // consequent (and immediate) retrieve request
    struct notification_context_t {
        // The timer used for internal db polling
        boost::asio::steady_timer timer;
        // the message is stored here momentarily; needed because
        // we can't pass it using current notification mechanism
        boost::optional<message_t> message;
    } notification_ctx_;

  public:
    connection_t(boost::asio::io_context& ioc, tcp::socket socket,
                 ServiceNode& sn,
                 ChannelEncryption<std::string>& channel_encryption);

    ~connection_t();

    /// Initiate the asynchronous operations associated with the connection.
    void start();

    void notify(const message_t& msg);

    /// "Reset" the connection by sending an empty message list
    void reset();

  private:
    /// Asynchronously receive a complete request message.
    void read_request();

    /// Check the database for new data, reschedule if empty
    void poll_db(const std::string& pk, const std::string& last_hash);

    /// Determine what needs to be done with the request message
    /// (synchronously).
    void process_request();

    void process_store(const nlohmann::json& params);

    void process_retrieve(const nlohmann::json& params);

    void process_snodes_by_pk(const nlohmann::json& params);

    void process_retrieve_all();

    template <typename T>
    void respond_with_messages(const std::vector<T>& messages);

    /// Asynchronously transmit the response message.
    void write_response();

    /// Syncronously (?) process client store/load requests
    void process_client_req();

    // Check whether we have spent enough time on this connection.
    void register_deadline();

    /// TODO: should move somewhere else

    bool parse_header(const char* key);

    template <typename... Args>
    bool parse_header(const char* first, Args... args);

    void handle_wrong_swarm(const std::string& pubKey);

    bool verify_signature();
};

void run(boost::asio::io_context& ioc, std::string& ip, uint16_t port,
         ServiceNode& sn, ChannelEncryption<std::string>& channelEncryption);

} // namespace http_server

} // namespace loki
