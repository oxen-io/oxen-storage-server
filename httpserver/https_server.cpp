#include "https_server.h"

#include "file.hpp"
#include "http.h"
#include "omq_server.h"
#include "oxen_logger.h"
#include "request_handler.h"
#include "service_node.h"
#include "signature.h"
#include "string_utils.hpp"

#include <boost/endian/conversion.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>
#include <variant>

namespace oxen {
using nlohmann::json;

// Sends an error response and finalizes the response.
void HTTPSServer::error_response(
        HttpResponse& res, http::response_code code, std::optional<std::string_view> body) const {
    res.writeStatus(std::to_string(code.first) + " " + std::string{code.second});
    add_generic_headers(res);
    res.writeHeader("Content-Type", "text/plain");
    if (closing_)
        res.writeHeader("Connection", "close");
    if (body)
        res.end(*body);
    else
        res.end(std::string{code.second} + "\n");
    if (closing_)
        res.close();
}

void HTTPSServer::handle_cors(HttpRequest& req, http::headers& extra_headers) {
    if (cors_any_)
        extra_headers.emplace("Access-Control-Allow-Origin", "*");
    else if (!cors_.empty()) {
        if (std::string origin{req.getHeader("origin")}; !origin.empty() && cors_.count(origin)) {
            extra_headers.emplace("Access-Control-Allow-Origin", "*");
            extra_headers.emplace("Vary", "Origin");
        }
    }
}

//------------------------------------------------------------------------------------------------------------------------------
HTTPSServer::HTTPSServer(
        ServiceNode& sn,
        RequestHandler& rh,
        RateLimiter& rl,
        std::vector<std::tuple<std::string, uint16_t, bool>> bind,
        const std::filesystem::path& ssl_cert,
        const std::filesystem::path& ssl_key,
        const std::filesystem::path& ssl_dh,
        legacy_keypair legacy_keys) :
        service_node_{sn},
        omq_{*service_node_.omq_server()},
        request_handler_{rh},
        rate_limiter_{rl},
        legacy_keys_{std::move(legacy_keys)},
        cert_signature_{oxenc::to_base64(util::view_guts(
                generate_signature(hash_data(slurp_file(ssl_cert)), legacy_keys_)))} {
    // Add a category for handling incoming https requests
    omq_.add_category(
            "https",
            oxenmq::AuthLevel::basic,
            2,    // minimum # of threads reserved threads for this category
            1000  // max queued requests
    );

    // uWS is designed to work from a single thread, which is good (we pull off the requests and
    // then stick them into the LMQ job queue to be scheduled along with other jobs).  But as a
    // consequence, we need to create everything inside that thread.  We *also* need to get the
    // (thread local) event loop pointer back from the thread so that we can shut it down later
    // (injecting a callback into it is one of the few thread-safe things we can do across
    // threads).
    //
    // Things we need in the owning thread, fulfilled from the http thread:

    // - the uWS::Loop* for the event loop thread (which is thread_local).  We can get this
    // during
    //   thread startup, after the thread does basic initialization.
    std::promise<uWS::Loop*> loop_promise;
    auto loop_future = loop_promise.get_future();

    // - the us_listen_socket_t* on which the server is listening.  We can't get this until we
    //   actually start listening, so wait until `start()` for it.  (We also double-purpose it
    //   to send back an exception if one fires during startup).
    std::promise<std::vector<us_listen_socket_t*>> startup_success_promise;
    startup_success_ = startup_success_promise.get_future();

    // Things we need to send from the owning thread to the event loop thread:
    // - a signal when the thread should bind to the port and start the event loop (when we call
    //   start()).
    // startup_promise_

    uWS::SocketContextOptions https_opts{
            .key_file_name = ssl_key.c_str(),
            .cert_file_name = ssl_cert.c_str(),
            .dh_params_file_name = ssl_dh.c_str()};

    server_thread_ = std::thread{
            [this, bind = std::move(bind), &https_opts](
                    std::promise<uWS::Loop*> loop_promise,
                    std::future<bool> startup_future,
                    std::promise<std::vector<us_listen_socket_t*>> startup_success) {
                uWS::SSLApp https{https_opts};
                try {
                    create_endpoints(https);
                } catch (...) {
                    loop_promise.set_exception(std::current_exception());
                    return;
                }
                // We've initialized, signal the calling thread
                loop_promise.set_value(uWS::Loop::get());
                // Now wait until we get the signal to go (sent when the caller calls start() call).
                if (!startup_future.get())
                    // False means cancel, i.e. we got destroyed/shutdown without start() being
                    // called
                    return;

                // we don't currently do cors
                // cors_ = {...};

                std::vector<us_listen_socket_t*> listening;
                try {
                    bool required_bind_failed = false;
                    for (const auto& [addr, port, required] : bind)
                        https.listen(
                                addr,
                                port,
                                LIBUS_LISTEN_EXCLUSIVE_PORT,
                                [&listening,
                                 req = required,
                                 &required_bind_failed,
                                 addr = fmt::format("{}:{}", addr, port)](
                                        us_listen_socket_t* sock) {
                                    if (sock) {
                                        OXEN_LOG(info, "HTTPS server listening at {}", addr);
                                        listening.push_back(sock);
                                    } else if (req) {
                                        required_bind_failed = true;
                                        OXEN_LOG(
                                                critical,
                                                "HTTPS server failed to bind to required address "
                                                "{}",
                                                addr);
                                    } else {
                                        OXEN_LOG(
                                                warn,
                                                "HTTPS server failed to bind to (non-required) "
                                                "address {}",
                                                addr);
                                    }
                                });

                    if (listening.empty() || required_bind_failed) {
                        std::ostringstream error;
                        error << "RPC HTTP server failed to bind; ";
                        if (listening.empty())
                            error << "no valid bind address(es) given; ";
                        error << "tried to bind to:";
                        for (const auto& [addr, port, required] : bind)
                            error << ' ' << addr << ':' << port;
                        throw std::runtime_error{error.str()};
                    }
                } catch (...) {
                    startup_success.set_exception(std::current_exception());
                    return;
                }
                startup_success.set_value(std::move(listening));

                https.run();
            },
            std::move(loop_promise),
            startup_promise_.get_future(),
            std::move(startup_success_promise)};

    loop_ = loop_future.get();
}

bool HTTPSServer::check_ready(HttpResponse& res) {
    if (std::string reason; !service_node_.snode_ready(&reason)) {
        OXEN_LOG(debug, "Storage server not ready ({}), replying with 503", reason);
        error_response(
                res, http::SERVICE_UNAVAILABLE, "Service node is not ready: " + reason + "\n");
        return false;
    }
    return true;
}

void HTTPSServer::add_generic_headers(HttpResponse& res) const {
    res.writeHeader("Server", server_header());
}

// Queues a response with the uWebSockets response object; this must only be called from the
// http thread (typically you want to use `queue_response` instead).
void queue_response_internal(
        HTTPSServer& https, HttpResponse& r, Response res, bool force_close = false) {
    r.cork([&https, &r, res = std::move(res), force_close] {
        r.writeStatus(fmt::format("{} {}", res.status.first, res.status.second));
        https.add_generic_headers(r);

        const bool is_json = std::holds_alternative<json>(res.body);
        if (std::none_of(begin(res.headers), end(res.headers), [](const auto& h) {
                return util::string_iequal(h.first, "content-type");
            }))
            r.writeHeader("Content-Type", is_json ? "application/json" : "text/plain");
        for (const auto& [h, v] : res.headers)
            r.writeHeader(h, v);

        // NB: if the dump() here throws then it means we messed up and put some invalid data
        // (probably binary) into a json value.
        r.end(is_json ? std::get<json>(res.body).dump() : view_body(res),
              force_close || https.closing());
    });
}

namespace {

    struct Request {
        std::string body;
        http::headers headers;
        std::string remote_addr;
        std::string uri;
    };

    struct call_data {
        HTTPSServer& https;
        oxenmq::OxenMQ& omq;
        HttpResponse& res;
        Request request;
        std::vector<std::pair<std::string, std::string>> extra_headers;
        bool aborted{false};
        bool replied{false};

        // If we have to drop the request because we are overloaded we want to reply with an
        // error (so that we close the connection instead of leaking it and leaving it hanging).
        // We don't do this, of course, if the request got aborted and replied to.
        ~call_data() {
            if (replied || aborted)
                return;
            https.loop_defer([&https = https, &res = res] {
                https.error_response(
                        res, http::SERVICE_UNAVAILABLE, "Server busy, try again later");
            });
        }

        call_data(const call_data&) = delete;
        call_data(call_data&&) = delete;
        call_data& operator=(const call_data&) = delete;
        call_data& operator=(call_data&&) = delete;

        template <typename... T>
        auto error_response(T&&... args) {
            if (replied || aborted)
                return;
            replied = true;
            return https.error_response(std::forward<T>(args)...);
        }
    };

    // Queues a response for the HTTP thread to handle; the response can be in multiple string
    // pieces to be concatenated together.
    void queue_response(std::shared_ptr<call_data> data, Response res, bool force_close = false) {
        if (!data || data->replied)
            return;
        data->replied = true;
        data->https.loop_defer(
                [data = std::move(data), res = std::move(res), force_close]() mutable {
                    if (data->aborted)
                        return;
                    queue_response_internal(data->https, data->res, std::move(res), force_close);
                });
    }

    std::string get_remote_address(HttpResponse& res) {
        std::ostringstream result;
        bool first = true;
        auto addr = res.getRemoteAddress();
        if (addr.size() == 4) {  // IPv4, packed into bytes
            for (auto c : addr) {
                if (first)
                    first = false;
                else
                    result << '.';
                result << +static_cast<uint8_t>(c);
            }
        } else if (addr.size() == 16) {
            // IPv6, packed into bytes.  Interpret as a series of 8 big-endian shorts and
            // convert to hex, joined with :.  But we also want to drop leading insignificant
            // 0's (i.e. '34f' instead of '034f'), and we want to collapse the longest sequence
            // of 0's that we come across (so that, for example, localhost becomes `::1` instead
            // of `0:0:0:0:0:0:0:1`).
            std::array<uint16_t, 8> a;
            std::memcpy(a.data(), addr.data(), 16);
            for (auto& x : a)
                boost::endian::big_to_native_inplace(x);

            size_t zero_start = 0, zero_end = 0;
            for (size_t i = 0, start = 0, end = 0; i < a.size(); i++) {
                if (a[i] != 0)
                    continue;
                if (end != i)  // This zero value starts a new zero sequence
                    start = i;
                end = i + 1;
                if (end - start > zero_end - zero_start) {
                    zero_end = end;
                    zero_start = start;
                }
            }
            result << '[' << std::hex;
            for (size_t i = 0; i < a.size(); i++) {
                if (i >= zero_start && i < zero_end) {
                    if (i == zero_start)
                        result << "::";
                    continue;
                }
                if (i > 0 && i != zero_end)
                    result << ':';
                result << a[i];
            }
            result << ']';
        } else
            result << "{unknown:" << oxenc::to_hex(addr) << "}";
        return result.str();
    }

    // Extracts a x25519 pubkey from a hex string. Warns and throws on invalid input.
    x25519_pubkey extract_x25519_from_hex(std::string_view hex) {
        try {
            return x25519_pubkey::from_hex(hex);
        } catch (const std::exception& e) {
            OXEN_LOG(warn, "Failed to decode ephemeral key in onion request: {}", e.what());
            throw;
        }
    }

    // Sets up a request handler that processes the initial incoming requests, sets up the
    // appropriate handlers for incoming data, and invokes the `ready` callback once all data
    // has been received (i.e. when the request is complete).  Can optionally call `prevalidate`
    // on the partial call_data: it will have everything except for the body set (and can be
    // used, for instance, to abort a request based only on headers); it will also be called
    // from the same thread calling handle_request (typically the http thread), *not* a worker
    // thread.
    template <typename ReadyCallback>
    static void handle_request(
            HTTPSServer& https,
            oxenmq::OxenMQ& omq,
            HttpRequest& req,
            HttpResponse& res,
            ReadyCallback ready,
            std::function<void(call_data& c)> prevalidate = nullptr) {
        if (auto len = req.getHeader("content-length"); !len.empty()) {
            if (uint64_t length; !util::parse_int(len, length)) {
                OXEN_LOG(
                        warn,
                        "Received HTTPS request from {} with invalid Content-Length, dropping",
                        get_remote_address(res));
                queue_response_internal(
                        https, res, Response{http::BAD_REQUEST, "invalid Content-Length"sv}, true);
            } else if (length > MAX_REQUEST_BODY_SIZE) {
                OXEN_LOG(
                        warn,
                        "Received HTTPS request from {} with too-large body ({} > {}), dropping",
                        get_remote_address(res),
                        length,
                        MAX_REQUEST_BODY_SIZE);
                queue_response_internal(
                        https,
                        res,
                        Response{http::PAYLOAD_TOO_LARGE, "Request body too large"sv},
                        true);
            }
        }

        std::shared_ptr<call_data> data{new call_data{https, omq, res}};
        auto& request = data->request;
        request.remote_addr = get_remote_address(res);
        request.uri = req.getUrl();
        for (const auto& [header, value] : req)
            request.headers[std::string{header}] = value;

        https.handle_cors(req, request.headers);
        OXEN_LOG(
                debug,
                "Received {} {} request from {}",
                req.getMethod(),
                request.uri,
                request.remote_addr);

        if (prevalidate)
            prevalidate(*data);

        res.onAborted([data] { data->aborted = true; });
        res.onData([data = std::move(data), ready = std::move(ready)](
                           std::string_view d, bool done) mutable {
            data->request.body += d;
            if (done)
                ready(std::move(data));
        });
    }

}  // anonymous namespace

void HTTPSServer::create_endpoints(uWS::SSLApp& https) {
    // Legacy target, can be removed post-HF18.1:
    https.post("/swarms/ping_test/v1", [this](HttpResponse* res, HttpRequest* req) {
        OXEN_LOG(trace, "Received (old) https ping_test");
        service_node_.update_last_ping(ReachType::HTTPS);
        Response resp{http::OK};
        resp.headers.emplace_back(http::SNODE_SIGNATURE_HEADER, cert_signature_);
        queue_response_internal(*this, *res, std::move(resp));
    });

    https.post("/ping_test/v1", [this](HttpResponse* res, HttpRequest* req) {
        OXEN_LOG(trace, "Received https ping_test");
        service_node_.update_last_ping(ReachType::HTTPS);
        Response resp{http::OK};
        resp.headers.emplace_back(
                http::SNODE_PUBKEY_HEADER, oxenc::to_base64(legacy_keys_.first.view()));
        queue_response_internal(*this, *res, std::move(resp));
    });

    // Legacy storage testing over HTTPS; can be removed after HF18.1
    https.post("/swarms/storage_test/v1", [this](HttpResponse* res, HttpRequest* req) {
        if (!check_ready(*res))
            return;
        process_storage_test_req(*req, *res);
    });
    https.post("/storage_rpc/v1", [this](HttpResponse* res, HttpRequest* req) {
        if (!check_ready(*res))
            return;
        OXEN_LOG(trace, "POST /storage_rpc/v1");
        process_storage_rpc_req(*req, *res);
    });
    https.post("/onion_req/v2", [this](HttpResponse* res, HttpRequest* req) {
        if (!check_ready(*res))
            return;
        OXEN_LOG(trace, "POST /onion_req/v2");
        process_onion_req_v2(*req, *res);
    });
    // Deprecated; use /storage_rpc/v1 with method=info instead
    https.get("/get_stats/v1", [this](HttpResponse* res, HttpRequest* req) {
        queue_response_internal(
                *this, *res, Response{http::OK, json{{"version", STORAGE_SERVER_VERSION_STRING}}});
    });

    // Fallback to send a 404 for anything else:
    https.any("/*", [this](HttpResponse* res, HttpRequest* req) {
        OXEN_LOG(
                info,
                "Invalid HTTP request for {} {} from {}",
                req->getMethod(),
                req->getUrl(),
                get_remote_address(*res));
        error_response(
                *res,
                http::NOT_FOUND,
                fmt::format("{} {} Not Found", req->getMethod(), req->getUrl()));
    });
}

/// Verifies snode pubkey and signature values in a request; returns the sender pubkey on
/// success or a filled-out error Response if verification fails.
///
/// `prevalidate` - if true, do a "pre-validation": check that the required header values
/// (pubkey, signature) are present and valid (including verifying that the pubkey is a valid
/// snode) but don't actually verify the signature against the body (note that this is *not*
/// signature verification but is used as a pre-check before reading a body to ensure the
///
/// Deprecated; can be removed after HF19
static std::variant<legacy_pubkey, Response> validate_snode_signature(
        ServiceNode& sn, const Request& r, bool prevalidate = false) {
    legacy_pubkey pubkey;
    if (auto it = r.headers.find(http::SNODE_SENDER_HEADER); it != r.headers.end())
        pubkey = parse_legacy_pubkey(it->second);
    if (!pubkey) {
        OXEN_LOG(debug, "Missing or invalid pubkey header for request");
        return Response{http::BAD_REQUEST, "missing/invalid pubkey header"sv};
    }
    signature sig;
    if (auto it = r.headers.find(http::SNODE_SIGNATURE_HEADER); it != r.headers.end()) {
        try {
            sig = signature::from_base64(it->second);
        } catch (...) {
            OXEN_LOG(warn, "invalid signature (not b64) found in header from {}", pubkey);
            return Response{http::BAD_REQUEST, "Invalid signature"sv};
        }
    } else {
        OXEN_LOG(debug, "Missing required signature header for request");
        return Response{http::BAD_REQUEST, "missing signature header"sv};
    }

    if (!sn.find_node(pubkey)) {
        OXEN_LOG(debug, "Rejecting signature from unknown service node: {}", pubkey);
        return Response{http::UNAUTHORIZED, "Unknown service node"sv};
    }

    if (!prevalidate) {
        if (!check_signature(sig, hash_data(r.body), pubkey)) {
            OXEN_LOG(debug, "snode signature verification failed for pubkey {}", pubkey);
            return Response{http::UNAUTHORIZED, "snode signature verification failed"sv};
        }
    }
    return pubkey;
}

void HTTPSServer::process_storage_test_req(HttpRequest& req, HttpResponse& res) {
    auto check_snode_headers = [this, &res](call_data& data) {
        // Before we read the body make sure we have the required headers (so that we can reject
        // bad requests earlier).
        if (auto prevalidate = validate_snode_signature(service_node_, data.request, true);
            std::holds_alternative<Response>(prevalidate)) {
            queue_response_internal(*this, res, std::move(std::get<Response>(prevalidate)));
            data.replied = true;
        } else {
            assert(std::holds_alternative<legacy_pubkey>(prevalidate));
            if (rate_limiter_.should_rate_limit(std::get<legacy_pubkey>(prevalidate))) {
                queue_response_internal(
                        *this,
                        res,
                        Response{http::TOO_MANY_REQUESTS, "too many requests from this snode"sv});
                data.replied = true;
            }
        }
    };

    handle_request(
            *this,
            omq_,
            req,
            res,
            [this](std::shared_ptr<call_data> data) mutable {
                // Now that we have the body, fully validate the snode signature:
                if (auto validate = validate_snode_signature(service_node_, data->request);
                    std::holds_alternative<Response>(validate))
                    return queue_response(std::move(data), std::move(std::get<Response>(validate)));

                auto& omq = data->omq;
                auto& request = data->request;
                omq.inject_task(
                        "https",
                        "https:" + request.uri,
                        request.remote_addr,
                        [this, data = std::move(data)]() mutable {
                            if (data->replied || data->aborted)
                                return;

                            auto& req = data->request;

                            Response resp{http::BAD_REQUEST};
                            resp.headers.emplace_back(
                                    http::SNODE_SIGNATURE_HEADER, cert_signature_);

                            legacy_pubkey tester_pk;
                            if (auto it = req.headers.find(http::SNODE_SENDER_HEADER);
                                it != req.headers.end()) {
                                if (tester_pk = parse_legacy_pubkey(it->second); !tester_pk) {
                                    OXEN_LOG(debug, "Invalid test request: invalid pubkey");
                                    resp.body = "invalid tester pubkey header"sv;
                                    return queue_response(std::move(data), std::move(resp));
                                }
                            } else {
                                OXEN_LOG(debug, "Invalid test request: missing pubkey");
                                resp.body = "missing tester pubkey header"sv;
                                return queue_response(std::move(data), std::move(resp));
                            }

                            auto body = json::parse(data->request.body, nullptr, false);
                            if (body.is_discarded()) {
                                OXEN_LOG(debug, "Bad snode test request: invalid json");
                                resp.body = "invalid json"sv;
                                return queue_response(std::move(data), std::move(resp));
                            }

                            uint64_t height;
                            std::string msg_hash;
                            try {
                                height = body.at("height").get<uint64_t>();
                                msg_hash = body.at("hash").get<std::string>();
                            } catch (...) {
                                resp.body = "Bad snode test request: missing fields in json"sv;
                                OXEN_LOG(debug, std::get<std::string_view>(resp.body));
                                return queue_response(std::move(data), std::move(resp));
                            }

                            request_handler_.process_storage_test_req(
                                    height,
                                    tester_pk,
                                    msg_hash,
                                    [data = std::move(data), resp = std::move(resp)](
                                            MessageTestStatus status,
                                            std::string answer,
                                            std::chrono::steady_clock::duration elapsed) mutable {
                                        resp.status = http::OK;
                                        switch (status) {
                                            case MessageTestStatus::SUCCESS:
                                                OXEN_LOG(
                                                        debug,
                                                        "Storage test success after {}",
                                                        util::friendly_duration(elapsed));
                                                resp.body =
                                                        json{{"status", "OK"},
                                                             {"value", oxenc::to_base64(answer)}};
                                                return queue_response(
                                                        std::move(data), std::move(resp));
                                            case MessageTestStatus::WRONG_REQ:
                                                resp.body = json{{"status", "wrong request"}};
                                                return queue_response(
                                                        std::move(data), std::move(resp));
                                            case MessageTestStatus::RETRY:
                                                [[fallthrough]];  // If we're getting called then a
                                                                  // retry ran out of time
                                            case MessageTestStatus::ERROR:
                                                // Promote this to `error` once we enforce storage
                                                // testing
                                                OXEN_LOG(
                                                        debug,
                                                        "Failed storage test, tried for {}",
                                                        util::friendly_duration(elapsed));
                                                resp.body = json{{"status", "other"}};
                                                return queue_response(
                                                        std::move(data), std::move(resp));
                                        }
                                    });
                        });
            },
            std::move(check_snode_headers));
}

bool HTTPSServer::should_rate_limit_client(std::string_view addr) {
    if (addr.size() != 4)
        return true;
    uint32_t ip;
    std::memcpy(&ip, addr.data(), 4);
    boost::endian::big_to_native_inplace(ip);
    return rate_limiter_.should_rate_limit_client(ip);
}

void HTTPSServer::process_storage_rpc_req(HttpRequest& req, HttpResponse& res) {
    auto addr = res.getRemoteAddress();
    if (addr.size() != 4) {
        // We don't (currently?) support IPv6 at all (SS published IPs are only IPv4) so if we
        // somehow get an IPv6 address then it isn't a proper SS request so just drop it.
        OXEN_LOG(warn, "incoming client request is not IPv4; dropping it");
        return error_response(res, http::BAD_REQUEST);
    }
    if (should_rate_limit_client(addr)) {
        OXEN_LOG(debug, "Rate limiting client request from {}", get_remote_address(res));
        return error_response(res, http::TOO_MANY_REQUESTS);
    }
    if (!req.getHeader("x-loki-long-poll").empty()) {
        // Obsolete header, return an error code
        return error_response(
                res, http::GONE, "long polling is no longer supported, client upgrade required");
    }

    handle_request(
            *this,
            omq_,
            req,
            res,
            [this,
             started = std::chrono::steady_clock::now()](std::shared_ptr<call_data> data) mutable {
                auto& omq = data->omq;
                auto& request = data->request;
                omq.inject_task(
                        "https",
                        "https:" + request.uri,
                        request.remote_addr,
                        [this, data = std::move(data), started]() mutable {
                            if (data->replied || data->aborted)
                                return;

                            try {
                                request_handler_.process_client_req(
                                        data->request.body,
                                        [data, started](Response response) mutable {
                                            OXEN_LOG(
                                                    debug,
                                                    "Responding to a client request after {}",
                                                    util::friendly_duration(
                                                            std::chrono::steady_clock::now()
                                                            - started));
                                            queue_response(std::move(data), std::move(response));
                                        });
                            } catch (const std::exception& e) {
                                auto error = "Exception caught with processing client request: "s
                                           + e.what();
                                OXEN_LOG(critical, "{}", error);
                                queue_response(
                                        std::move(data), {http::INTERNAL_SERVER_ERROR, error});
                            }
                        });
            });
}

void HTTPSServer::process_onion_req_v2(HttpRequest& req, HttpResponse& res) {
    handle_request(
            *this,
            omq_,
            req,
            res,
            [this,
             started = std::chrono::steady_clock::now()](std::shared_ptr<call_data> data) mutable {
                auto& omq = data->omq;
                auto& request = data->request;
                omq.inject_task(
                        "https",
                        "https:" + request.uri,
                        request.remote_addr,
                        [this, data = std::move(data), started]() mutable {
                            if (data->replied || data->aborted)
                                return;

                            OnionRequestMetadata onion{
                                    x25519_pubkey{},
                                    [data, started](Response res) {
                                        OXEN_LOG(
                                                debug,
                                                "Got an onion response ({} {}) as edge node (after "
                                                "{})",
                                                res.status.first,
                                                res.status.second,
                                                util::friendly_duration(
                                                        std::chrono::steady_clock::now()
                                                        - started));
                                        queue_response(std::move(data), std::move(res));
                                    },
                                    0,  // hopno
                                    EncryptType::aes_gcm,
                            };

                            try {
                                auto [ciphertext, json_req] =
                                        parse_combined_payload(data->request.body);

                                onion.ephem_key = extract_x25519_from_hex(
                                        json_req.at("ephemeral_key").get_ref<const std::string&>());

                                if (auto it = json_req.find("enc_type"); it != json_req.end())
                                    onion.enc_type =
                                            parse_enc_type(it->get_ref<const std::string&>());
                                // Otherwise stay at default aes-gcm

                                // Allows a fake starting hop number (to make it harder for
                                // intermediate hops to know where they are).  If omitted, defaults
                                // to 0.
                                if (auto it = json_req.find("hop_no"); it != json_req.end())
                                    onion.hop_no = std::max(0, it->get<int>());

                                request_handler_.process_onion_req(ciphertext, std::move(onion));
                            } catch (const std::exception& e) {
                                auto msg = fmt::format("Error parsing onion request: {}", e.what());
                                OXEN_LOG(err, "{}", msg);
                                queue_response(std::move(data), {http::BAD_REQUEST, msg});
                            }
                        });
            });
}

void HTTPSServer::start() {
    if (sent_startup_)
        throw std::logic_error{"Cannot call HTTPSServer::start() more than once"};

    startup_promise_.set_value(true);
    sent_startup_ = true;
    listen_socks_ = startup_success_.get();
}

void HTTPSServer::shutdown(bool join) {
    if (!server_thread_.joinable())
        return;

    if (!sent_shutdown_) {
        OXEN_LOG(trace, "initiating shutdown");
        if (!sent_startup_) {
            startup_promise_.set_value(false);
            sent_startup_ = true;
        } else if (!listen_socks_.empty()) {
            loop_defer([this] {
                OXEN_LOG(trace, "closing {} listening sockets", listen_socks_.size());
                for (auto* s : listen_socks_)
                    us_listen_socket_close(/*ssl=*/true, s);
                listen_socks_.clear();

                closing_ = true;
            });
        }
        sent_shutdown_ = true;
    }

    OXEN_LOG(trace, "joining https server thread");
    if (join)
        server_thread_.join();
    OXEN_LOG(trace, "done shutdown");
}

HTTPSServer::~HTTPSServer() {
    shutdown(true);
}

}  // namespace oxen
