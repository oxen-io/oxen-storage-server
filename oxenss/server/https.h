#pragma once

#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/version.h>
#include "utils.h"

#include <filesystem>
#include <future>
#include <unordered_set>

#include <uWebSockets/App.h>

namespace oxenssmq {
class OxenMQ;
}

namespace oxenss::server {
using namespace std::literals;

// Maximum incoming HTTPS request size, in bytes.
inline constexpr uint64_t MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024;

// Full uWebSocket http request/response objects:
using HttpRequest = uWS::HttpRequest;
using HttpResponse = uWS::HttpResponse<true /*SSL*/>;

class HTTPS {
  public:
    // Construct the https server listening on one or more addresses.
    //
    // \param bind {address,port,required} tuples to bind to.  If `required` is set then the
    // constructor will throw if binding fails, if not then the construction will succeed as
    // long as at least one bind address works.
    HTTPS(snode::ServiceNode& sn,
          rpc::RequestHandler& rh,
          rpc::RateLimiter& rl,
          std::vector<std::tuple<std::string, uint16_t, bool>> bind,
          const std::filesystem::path& ssl_cert,
          const std::filesystem::path& ssl_key,
          const std::filesystem::path& ssl_dh,
          crypto::legacy_keypair legacy_keys);

    ~HTTPS();

    /// Starts the event loop in the thread handling http requests.  Core must have been
    /// initialized and OxenMQ started.  Will propagate an exception from the thread if startup
    /// fails.
    void start();

    /// Closes the http server connection.  Can safely be called multiple times, or to abort a
    /// startup if called before start().
    ///
    /// \param join - if true, wait for the server thread to exit.  If false then joining will
    /// occur during destruction.
    void shutdown(bool join = false);

    // Adds headers that go onto every request such as X-Loki-Snode-Signature and Server
    void add_generic_headers(HttpResponse& res) const;

    // Sends an error response and finalizes the response.  If body is empty, uses the default
    // error response text.
    void error_response(
            HttpResponse& res,
            http::response_code code,
            std::optional<std::string_view> body = std::nullopt) const;

    /// handles cors headers by adding any needed headers to the given vector
    void handle_cors(HttpRequest& req, http::headers& extra_headers);

    // Posts a callback to the uWebSockets thread loop controlling this connection; all writes
    // must be done from that thread, and so this method is provided to defer a callback from
    // another thread into that one.  The function should have signature `void ()`.
    template <typename Func>
    void loop_defer(Func&& f) {
        loop_->defer(std::forward<Func>(f));
    }

    const std::string& server_header() const { return server_header_; }

    bool closing() const { return closing_; }

    snode::ServiceNode& service_node() { return service_node_; }

  private:
    // Checks whether the snode is ready; if not, sets an error message and returns false (the
    // handler should return immediately).
    bool check_ready(HttpResponse& res);

    void create_endpoints(uWS::SSLApp& http);

    bool should_rate_limit_client(std::string_view addr);

    void process_storage_rpc_req(HttpRequest& req, HttpResponse& res);
    void process_onion_req_v2(HttpRequest& req, HttpResponse& res);

    // A promise we send from outside into the event loop thread to signal it to start.  We sent
    // "true" to go ahead with binding + starting the event loop, or false to abort.
    std::promise<bool> startup_promise_;
    // A future (promise held by the thread) that delivers us the listening uSockets sockets so
    // that, when we want to shut down, we can tell uWebSockets to close them (which will then
    // run off the end of the event loop).  This also doubles to propagate listen exceptions
    // back to us.
    std::future<std::vector<us_listen_socket_t*>> startup_success_;
    // Whether we have sent the startup/shutdown signals
    bool sent_startup_{false}, sent_shutdown_{false};

    // The uWebSockets event loop pointer (so that we can inject a callback to shut it down)
    uWS::Loop* loop_{nullptr};
    // The socket(s) we are listening on
    std::vector<us_listen_socket_t*> listen_socks_;
    // The thread in which the uWebSockets event listener is running
    std::thread server_thread_;
    // Cached string we send for the Server header
    std::string server_header_ =
            "Oxen Storage Server/" + std::string{STORAGE_SERVER_VERSION_STRING};
    // Access-Control-Allow-Origin header values; if one of these match the incoming Origin
    // header we return it in the ACAO header; otherwise (or if this is empty) we omit the
    // header entirely.
    std::unordered_set<std::string> cors_;
    // Will be set to true when we're trying to shut down which closes any connections as we
    // reply to them.  Should only be read/write from inside the uWS loop.
    bool closing_ = false;
    // If true then always reply with 'Access-Control-Allow-Origin: *' to allow anything.
    bool cors_any_ = false;
    // Our owning service node
    snode::ServiceNode& service_node_;
    // OMQ reference (from service_node_)
    oxenmq::OxenMQ& omq_;
    // Request handler
    rpc::RequestHandler& request_handler_;
    // Rate limiter for direct client requests
    rpc::RateLimiter& rate_limiter_;
    // Keys for signing responses
    crypto::legacy_keypair legacy_keys_;

    friend void queue_response_internal(
            HTTPS& https, HttpResponse& r, rpc::Response res, bool force_close);
};

}  // namespace oxenss::server
