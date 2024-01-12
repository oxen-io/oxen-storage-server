#include "mqbase.h"
#include <sodium/crypto_sign.h>
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "utils.h"

namespace oxenss::server {

static auto logcat = log::Cat("server");

void MQBase::handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<sub_info>& subs) {

    // Values we receive, in bt-dict order:
    std::string_view ed_pk;                         // P (ed25519 pubkey only for session ids)
    std::optional<signed_subaccount_token> subacc;  // S (token signature), T (token)
    bool want_data = false;                         // d (given and true if data is desired)
    using namespace_int = std::underlying_type_t<namespace_id>;
    std::vector<namespace_id> namespaces;  // n (ordered list of numeric namespaces)
    std::string pubkey;                    // p (network id + ed25519 pubkey; not a session id)
    std::string_view signature;            // s (signature, by subacc.token.pubkey() or pubkey)
    std::chrono::seconds timestamp;        // t

    try {
        // Ed25519 pubkey for a Session ID (required if `p` is not present)
        if (d.skip_until("P")) {
            ed_pk = d.consume_string_view();
            if (ed_pk.size() != 32)
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided P= Session Ed25519 pubkey must be 32 bytes");
        }

        // Subaccount signature & token
        if (d.skip_until("S")) {
            subacc.emplace();
            if (auto sig = d.consume_string_view(); sig.size() == subacc->signature.size())
                std::memcpy(subacc->signature.data(), sig.data(), sig.size());
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided S subaccount signature must be {} bytes"_format(
                                subacc->signature.size()));

            if (auto token = d.require<std::string_view>("T");
                token.size() == SUBACCOUNT_TOKEN_LENGTH)
                std::memcpy(subacc->token.token.data(), token.data(), token.size());
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided T subaccount token must be {} bytes"_format(
                                SUBACCOUNT_TOKEN_LENGTH));
        }

        // Flag to send full message data as part of the pushed notifications (optional)
        if (d.skip_until("d"))
            want_data = d.consume_integer<bool>();

        // List of namespaces to monitor (required)
        auto ns = d.require<oxenc::bt_list_consumer>("n");
        namespaces.push_back(static_cast<namespace_id>(ns.consume_integer<namespace_int>()));
        while (!ns.is_finished()) {
            auto nsi = static_cast<namespace_id>(ns.consume_integer<namespace_int>());
            if (nsi > namespaces.back())
                namespaces.push_back(nsi);
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_NS,
                        "Invalid n= namespace list: namespaces must be ascending");
        }

        // Account ID (i.e. network prefix followed by an Ed25519 pubkey).  *Not* for Session
        // IDs, which must use P instead (because Session IDs are X25519 pubkeys).
        if (d.skip_until("p")) {
            if (!ed_pk.empty())
                throw std::runtime_error{"Cannot provide both p= and P= pubkey values"};
            pubkey = d.consume_string();
            if (pubkey.size() != 33)
                monitor_error(
                        out, MonitorResponse::BAD_PUBKEY, "Provided p= pubkey must be 33 bytes");
        } else if (ed_pk.empty()) {
            throw std::runtime_error{"Either p= or P= must be given"};
        }

        signature = d.require<std::string_view>("s");
        if (signature.size() != 64)
            return monitor_error(
                    out, MonitorResponse::BAD_SIG, "Provided s= signature must be 64 bytes");

        if (!d.skip_until("t"))
            throw std::runtime_error{"required signature timestamp is missing"};
        timestamp = std::chrono::seconds{d.consume_integer<int64_t>()};

    } catch (const std::exception& ex) {
        return monitor_error(out, MonitorResponse::BAD_ARGS, "Invalid arguments: "s + ex.what());
    }

    // Make sure the sig timestamp isn't too old or too new
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::time_point(timestamp);
    if (bool too_old = ts < now - 14 * 24h; too_old || ts > now + 24h) {
        return monitor_error(
                out,
                MonitorResponse::BAD_TS,
                "Invalid t= signature timestamp: timestamp is "s +
                        (too_old ? "too old" : "in the future"));
    }

    // If given an Ed25519 pubkey for a Session ID, derive the Session ID
    if (!ed_pk.empty()) {
        pubkey.resize(33);
        pubkey[0] = 0x05;
        if (auto rc = crypto_sign_ed25519_pk_to_curve25519(
                    reinterpret_cast<unsigned char*>(pubkey.data() + 1),
                    reinterpret_cast<const unsigned char*>(ed_pk.data()));
            rc != 0)
            return monitor_error(out, MonitorResponse::BAD_PUBKEY, "Invalid P= ed25519 public key");
    } else {
        // No Session Ed25519, so assume the pubkey (without prefix byte) is Ed25519
        ed_pk = pubkey;
        ed_pk.remove_prefix(1);
    }

    std::string_view verify_key = ed_pk;
    if (subacc) {
        try {
            subacc->verify(
                    pubkey[0],
                    reinterpret_cast<const unsigned char*>(ed_pk.data()),
                    subaccount_access::Read);
        } catch (const std::exception& ex) {
            auto m = "Subaccount verification failed: {}"_format(ex.what());
            log::warning(logcat, "{}", m);
            return monitor_error(out, MonitorResponse::BAD_SIG, m);
        }
        auto sub_pk = subacc->token.pubkey();
        verify_key = std::string_view{reinterpret_cast<const char*>(sub_pk.data()), sub_pk.size()};
    }
    assert(verify_key.size() == 32);

    auto pubkey_hex = oxenc::to_hex(pubkey);

    auto sig_msg = fmt::format(
            "MONITOR{:s}{:d}{:d}{}",
            pubkey_hex,
            timestamp.count(),
            want_data,
            fmt::join(namespaces, ","));

    if (0 != crypto_sign_verify_detached(
                     reinterpret_cast<const unsigned char*>(signature.data()),
                     reinterpret_cast<const unsigned char*>(sig_msg.data()),
                     sig_msg.size(),
                     reinterpret_cast<const unsigned char*>(verify_key.data()))) {
        log::debug(logcat, "monitor.messages signature verification failed");
        return monitor_error(out, MonitorResponse::BAD_SIG, "Signature verification failed");
    }

    subs.emplace_back(std::move(pubkey), std::move(pubkey_hex), std::move(namespaces), want_data);
    out.append("success", 1);
}

void MQBase::handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<sub_info>& subs) {
    handle_monitor_message_single(d, out, subs);
}

bool MQBase::handle_client_rpc(
        std::string_view name,
        std::string_view params,
        const std::string& remote_addr,
        std::function<void(http::response_code, std::string_view)> reply,
        bool forwarded) {
    // Check client rpc endpoints
    auto it = rpc::RequestHandler::client_rpc_endpoints.find(name);
    if (it == rpc::RequestHandler::client_rpc_endpoints.end())
        return false;

    auto& handler = it->second.mq;

    if (!forwarded && rate_limiter_->should_rate_limit_client(remote_addr)) {
        log::debug(logcat, "Rate limiting client request from {}", remote_addr);
        reply(http::TOO_MANY_REQUESTS, "Too many requests, try again later"sv);
        return true;
    }

    try {
        handler(*request_handler_,
                params,
                forwarded,
                [this, reply, bt_encoded = !params.empty() && params.front() == 'd'](
                        rpc::Response res) mutable {
                    std::string_view body;
                    std::string dump;

                    if (auto* j = std::get_if<nlohmann::json>(&res.body)) {
                        nlohmann::json resp = wrap_response(res.status, std::move(*j));
                        if (bt_encoded)
                            dump = bt_serialize(json_to_bt(std::move(resp)));
                        else
                            dump = resp.dump();
                        body = dump;
                    } else {
                        body = view_body(res);
                    }

                    log::debug(
                            logcat,
                            "RPC request {} ({}), returning {}-byte {} response",
                            res.status == http::OK ? "successful" : "failed",
                            res.status.first,
                            body.size(),
                            dump.empty() ? "raw"
                            : bt_encoded ? "bt-encoded"
                                         : "json");

                    reply(res.status, body);
                });
    } catch (const rpc::parse_error& e) {
        // These exceptions carry a failure message to send back to the client
        log::debug(logcat, "Invalid request: {}", e.what());
        reply(http::BAD_REQUEST, "invalid request: "s + e.what());
    } catch (const std::exception& e) {
        // Other exceptions might contain something sensitive or irrelevant so warn about it and
        // send back a generic message.
        log::warning(logcat, "Client request raised an exception: {}", e.what());
        reply(http::INTERNAL_SERVER_ERROR, "request failed");
    }
    return true;
}

void MQBase::handle_monitor(
        std::string_view request, std::function<void(std::string)> reply, connection_id conn) {
    if (request.size() < 2 || !(request.front() == 'd' || request.front() == 'l') ||
        request.back() != 'e') {
        reply(oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error",
                 "Invalid arguments: monitor request takes a single bencoded dict or list "
                 "parameter"}}));
        return;
    }

    std::string result;
    std::vector<sub_info> subs;
    try {
        if (request.front() == 'd') {
            oxenc::bt_dict_producer out;
            handle_monitor_message_single(oxenc::bt_dict_consumer{request}, out, subs);
            result = std::move(out).str();
        } else {
            oxenc::bt_list_producer out;
            oxenc::bt_list_consumer l{request};
            while (!l.is_finished())
                handle_monitor_message_single(l.consume_dict_consumer(), out.append_dict(), subs);
            result = std::move(out).str();
        }
    } catch (const std::exception& e) {
        reply(oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error", "Invalid arguments: Failed to parse monitor.messages data value"}}));
        return;
    }

    if (not subs.empty())
        update_monitors(subs, conn);

    reply(result);
}

namespace {
    // Merges sorted vectors a and b together, returns the sorted, combined vector (but without any
    // duplicates).  We avoid reallocating the vectors when possible (i.e. if either is a subset of
    // the other).
    std::vector<namespace_id> merge_namespaces(
            std::vector<namespace_id> a, std::vector<namespace_id> b) {
        // If the first arg of b comes before a, then our only subset case can be b as a superset of
        // a, so swap arguments so that the subset case always involves `a` as the superset.
        if (!b.empty() && (a.empty() || b.front() < a.front()))
            a.swap(b);
        // Figure out if a is a superset of b (in which case we can just return a):
        auto ita = a.begin(), itb = b.begin();
        while (ita != a.end() && itb != b.end()) {
            if (*itb > *ita)
                ita++;  // We have an element only in a, which is fine, skip it
            else if (*itb == *ita) {
                ita++;  // The element is in both, which is fine.
                itb++;
            } else
                break;  // We found a b that isn't in a, so we don't have a subset.
        }
        if (itb == b.end())
            return a;  // We hit the end of b without any violations above, which means everything
                       // in b is already in a.

        // Otherwise we need to merge them into a new sorted container c:
        std::vector<namespace_id> c;
        ita = a.begin();
        itb = b.begin();
        while (ita != a.end() || itb != b.end()) {
            if (itb == b.end())
                c.push_back(*ita++);
            else if (ita == a.end())
                c.push_back(*itb++);
            else if (*ita < *itb)
                c.push_back(*ita++);
            else if (*ita == *itb) {
                c.push_back(*ita++);
                itb++;  // Value is in both vectors, but we only want it once
            } else
                c.push_back(*itb++);
        }
        return c;
    }

}  // namespace

void MQBase::update_monitors(std::vector<sub_info>& subs, connection_id conn) {
    std::unique_lock lock{monitoring_mutex_};
    for (auto& [pubkey, pubkey_hex, namespaces, want_data] : subs) {
        bool found = false;
        for (auto [it, end] = monitoring_.equal_range(pubkey); it != end; ++it) {
            auto& mon_data = it->second;
            if (mon_data.conn == conn) {
                mon_data.namespaces =
                        merge_namespaces(std::move(mon_data.namespaces), std::move(namespaces));
                log::debug(
                        logcat,
                        "sub renewed for {} monitoring namespace(s) {}",
                        pubkey_hex,
                        fmt::join(mon_data.namespaces, ", "));
                mon_data.reset_expiry();
                mon_data.want_data |= want_data;
                found = true;
                break;
            }
        }
        if (not found) {
            log::debug(
                    logcat,
                    "new subscription for {} monitoring namespace(s) {}",
                    pubkey_hex,
                    fmt::join(namespaces, ", "));
            monitoring_.emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(std::move(pubkey)),
                    std::forward_as_tuple(std::move(namespaces), want_data, conn));
        }
    }
}

void MQBase::get_notifiers(
        message& m, std::vector<connection_id>& to, std::vector<connection_id>& with_data) {
    auto now = std::chrono::steady_clock::now();
    std::shared_lock lock{monitoring_mutex_};

    for (auto [it, end] = monitoring_.equal_range(m.pubkey.prefixed_raw()); it != end; ++it) {
        const auto& mon_data = it->second;
        auto& vec = mon_data.want_data ? with_data : to;
        if (mon_data.expiry >= now &&
            std::binary_search(
                    mon_data.namespaces.begin(), mon_data.namespaces.end(), m.msg_namespace))
            vec.push_back(mon_data.conn);
    }
}

}  // namespace oxenss::server
