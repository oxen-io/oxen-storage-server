#include "http_client.h"
#include <curl/curl.h>
#include <chrono>
#include <oxen/log.hpp>
#include <cpr/ssl_options.h>
#include <oxenss/version.h>

#include <event2/event.h>

namespace oxenss::http {

namespace log = oxen::log;

auto logcat = log::Cat("http");

struct curl_context {
    Client& client;
    curl_socket_t sockfd;
    event* evt;

    curl_context(Client& client, curl_socket_t fd) :
            client{client},
            sockfd{fd},
            evt{event_new(client.loop.get_event_base(), sockfd, 0, Client::curl_perform_c, this)} {}
    ~curl_context() {
        event_del(evt);
        event_free(evt);
    }
};

void Client::curl_perform_c(int /*fd*/, short event, void* cctx) {
    int running_handles;
    int flags = 0;
    auto* ctx = static_cast<curl_context*>(cctx);
    auto& client = ctx->client;

    if (event & EV_READ)
        flags |= CURL_CSELECT_IN;
    if (event & EV_WRITE)
        flags |= CURL_CSELECT_OUT;

    curl_multi_socket_action(client.curl_multi, ctx->sockfd, flags, &running_handles);
    // Can't use `ctx` anymore because it might have been destroyed during the above call (typically
    // because the socket is no longer being polled).

    client.check_multi_info();
}

void Client::on_timeout() {
    int running_handles;
    curl_multi_socket_action(curl_multi, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    check_multi_info();
}

int Client::start_timeout_c(CURLM* /*multi*/, long timeout_ms, void* userp) {
    auto& client = *static_cast<Client*>(userp);
    evtimer_del(client.ev_timeout);
    if (timeout_ms >= 0) {
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (timeout_ms == 0)
            tv.tv_usec = 1; /* 0 means call socket_action asap */
        evtimer_add(client.ev_timeout, &tv);
    }
    return 0;
}

int Client::handle_socket_c(
        CURL* /*easy*/, curl_socket_t s, int action, void* userp, void* socketp) {
    auto& client = *static_cast<Client*>(userp);
    auto* curl_ctx = static_cast<curl_context*>(socketp);
    int events = 0;

    switch (action) {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
            if (!curl_ctx) {
                curl_ctx = new curl_context{client, s};
                curl_multi_assign(client.curl_multi, s, curl_ctx);
            }

            if (action != CURL_POLL_IN)
                events |= EV_WRITE;
            if (action != CURL_POLL_OUT)
                events |= EV_READ;

            events |= EV_PERSIST;

            event_del(curl_ctx->evt);
            event_assign(
                    curl_ctx->evt,
                    client.loop.get_event_base(),
                    curl_ctx->sockfd,
                    events,
                    Client::curl_perform_c,
                    curl_ctx);
            event_add(curl_ctx->evt, NULL);

            break;
        case CURL_POLL_REMOVE:
            if (curl_ctx) {
                curl_multi_assign(client.curl_multi, s, nullptr);
                delete curl_ctx;
            }
            break;
        default: log::error(logcat, "Unexpected socket action {} from libcurl", action);
    }

    return 0;
}

void Client::check_multi_info() {
    int pending;
    while (CURLMsg* message = curl_multi_info_read(curl_multi, &pending)) {
        if (message->msg == CURLMSG_DONE) {
            cpr::Session* raw_sess;
            curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &raw_sess);
            assert(raw_sess);
            auto session = raw_sess->shared_from_this();
            assert(session);
            auto resp = session->Complete(message->data.result);
            auto it = active_reqs.find(session);
            assert(it != active_reqs.end());
            if (it->second) {
                try {
                    it->second(std::move(resp));
                } catch (const std::exception& e) {
                    log::error(logcat, "HTTP response handler raised exception: {}", e.what());
                }
            }
            active_reqs.erase(it);
            curl_multi_remove_handle(curl_multi, message->easy_handle);
        } else {
            log::warning(
                    logcat,
                    "Unexpected/unhandled curl-multi message type: {}",
                    static_cast<int>(message->msg));
        }
    }
}

Client::Client(oxen::quic::Loop& loop_) :
        loop{loop_},
        ev_timeout{evtimer_new(
                loop.get_event_base(),
                [](evutil_socket_t /*fd*/, short /*events*/, void* arg) {
                    static_cast<Client*>(arg)->on_timeout();
                },
                this)} {
    curl_multi = curl_multi_init();
    curl_multi_setopt(curl_multi, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(curl_multi, CURLMOPT_SOCKETFUNCTION, Client::handle_socket_c);
    curl_multi_setopt(curl_multi, CURLMOPT_TIMERDATA, this);
    curl_multi_setopt(curl_multi, CURLMOPT_TIMERFUNCTION, Client::start_timeout_c);
}

Client::~Client() {
    loop.call_get([this] {
        alive.reset();
        for (auto& [session, cb] : active_reqs)
            curl_multi_remove_handle(curl_multi, session->GetCurlHolder()->handle);
        active_reqs.clear();
        curl_multi_cleanup(curl_multi);
        event_free(ev_timeout);
    });
}

void Client::post(
        response_callback cb,
        std::string url,
        std::string payload,
        std::chrono::milliseconds timeout,
        std::optional<std::string> host_override,
        bool https_disable_validation) {
    auto sess = std::make_shared<cpr::Session>();
    sess->SetUrl(std::move(url));
    cpr::Header header{
            {"User-Agent", fmt::format("Oxen Storage Server/{}", STORAGE_SERVER_VERSION_STRING)},
            {"Content-Type", "application/octet-stream"}};
    if (host_override)
        header["Host"] = *host_override;
    sess->SetHeader(std::move(header));
    sess->SetTimeout(timeout);
    auto ssl_opts = cpr::Ssl(cpr::ssl::TLSv1_2{});  // TLSv1_2 means "1.2 or later"
    if (https_disable_validation) {
        ssl_opts.SetOption(cpr::ssl::VerifyHost{false});
        ssl_opts.SetOption(cpr::ssl::VerifyPeer{false});
        ssl_opts.SetOption(cpr::ssl::VerifyStatus{false});
    }
    sess->SetSslOptions(std::move(ssl_opts));
    sess->SetRedirect(cpr::Redirect{0L});
    sess->SetBody(std::move(payload));
    curl_easy_setopt(sess->GetCurlHolder()->handle, CURLOPT_PRIVATE, sess.get());
    sess->PreparePost();
    loop.call([this,
               alive = std::weak_ptr{alive},
               sess = std::move(sess),
               cb = std::move(cb)]() mutable {
        if (alive.expired())
            return;  // this got destroyed before we got into the call
        curl_multi_add_handle(curl_multi, sess->GetCurlHolder()->handle);
        active_reqs.emplace(std::move(sess), std::move(cb));
    });
}

}  // namespace oxenss::http
