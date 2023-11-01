#include "omq.h"
#include "../common/namespace.h"
#include "../rpc/client_rpc_endpoints.h"
#include "../utils/time.hpp"

#include <chrono>
#include <oxen/log.hpp>
#include <tuple>
#include <type_traits>
#include <utility>
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

namespace oxen::server {

using namespace std::literals;

static auto logcat = log::Cat("monitor");

namespace {

    enum class MonitorResponse {
        BAD_ARGS = 1,
        BAD_PUBKEY = 2,
        BAD_NS = 3,
        BAD_TS = 4,
        BAD_SIG = 5,
        WRONG_SWARM = 6,
    };

    void monitor_error(oxenc::bt_dict_producer& out, MonitorResponse r, std::string message) {
        out.append("errcode", static_cast<std::underlying_type_t<MonitorResponse>>(r));
        out.append("error", std::move(message));
    }

    // {pubkey (bytes), pubkey (hex), namespaces, want_data}
    using sub_info = std::tuple<std::string, std::string, std::vector<namespace_id>, bool>;

    void handle_monitor_message_single(
            oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<sub_info>& subs) {

        // Values we receive, in bt-dict order:
        std::string_view ed_pk;       // P
        std::string_view subkey_tag;  // S
        bool want_data = false;       // d
        using namespace_int = std::underlying_type_t<namespace_id>;
        std::vector<namespace_id> namespaces;  // n
        std::string pubkey;                    // p
        std::string_view signature;            // s
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

            // Subkey tag for subkey auth (optional)
            if (d.skip_until("S")) {
                subkey_tag = d.consume_string_view();
                if (subkey_tag.size() != 32)
                    return monitor_error(
                            out,
                            MonitorResponse::BAD_PUBKEY,
                            "Provided S= subkey tag must be 32 bytes");
            }

            // Send full data (optional)
            if (d.skip_until("d"))
                want_data = d.consume_integer<bool>();

            // List of namespaces to monitor (required)
            if (d.skip_until("n")) {
                auto ns = d.consume_list_consumer();
                namespaces.push_back(
                        static_cast<namespace_id>(ns.consume_integer<namespace_int>()));
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
            } else {
                throw std::runtime_error{"required namespace list is missing"};
            }

            if (d.skip_until("p")) {
                if (!ed_pk.empty())
                    throw std::runtime_error{"Cannot provide both p= and P= pubkey values"};
                pubkey = d.consume_string();
                if (pubkey.size() != 33)
                    monitor_error(
                            out,
                            MonitorResponse::BAD_PUBKEY,
                            "Provided p= pubkey must be 33 bytes");
            } else if (ed_pk.empty()) {
                throw std::runtime_error{"Either p= or P= must be given"};
            }

            if (!d.skip_until("s"))
                throw std::runtime_error{"required signature is missing"};
            signature = d.consume_string_view();
            if (signature.size() != 64)
                return monitor_error(
                        out, MonitorResponse::BAD_SIG, "Provided s= signature must be 64 bytes");

            if (!d.skip_until("t"))
                throw std::runtime_error{"required signature timestamp is missing"};
            timestamp = std::chrono::seconds{d.consume_integer<int64_t>()};

        } catch (const std::exception& ex) {
            return monitor_error(
                    out,
                    MonitorResponse::BAD_ARGS,
                    fmt::format("Invalid arguments: invalid {}= value: {}", d.key(), ex.what()));
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
                return monitor_error(
                        out, MonitorResponse::BAD_PUBKEY, "Invalid P= ed25519 public key");
        } else {
            // No Session Ed25519, so assume the pubkey (without prefix byte) is Ed25519
            ed_pk = pubkey;
            ed_pk.remove_prefix(1);
        }

        std::string_view verify_key = ed_pk;
        std::array<unsigned char, 32> subkey_pub;
        if (!subkey_tag.empty()) {
            try {
                subkey_pub = crypto::subkey_verify_key(ed_pk, subkey_tag);
            } catch (const std::invalid_argument& ex) {
                auto m = fmt::format("Signature verification failed: {}", ex.what());
                log::warning(logcat, "{}", m);
                return monitor_error(out, MonitorResponse::BAD_SIG, m);
            }
            verify_key = std::string_view{
                    reinterpret_cast<const char*>(subkey_pub.data()), subkey_pub.size()};
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

        subs.emplace_back(
                std::move(pubkey), std::move(pubkey_hex), std::move(namespaces), want_data);
        out.append("success", 1);
    }

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

void OMQ::handle_monitor_messages(oxenmq::Message& message) {
    if (message.data.size() != 1 || message.data[0].size() < 2 ||
        !(message.data[0].front() == 'd' || message.data[0].front() == 'l') ||
        message.data[0].back() != 'e') {
        message.send_reply(oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error",
                 "Invalid arguments: monitor.messages takes a single bencoded dict/list "
                 "parameter"}}));
        return;
    }
    const auto& m = message.data[0];

    std::string result;
    std::vector<sub_info> subs;
    try {
        if (m.front() == 'd') {
            result.resize(256);
            oxenc::bt_dict_producer out{result.data(), result.size()};
            handle_monitor_message_single(oxenc::bt_dict_consumer{m}, out, subs);
            result.resize(out.view().size());
        } else {
            result += 'l';
            oxenc::bt_list_consumer l{m};
            std::array<char, 256> buf;
            while (!l.is_finished()) {
                oxenc::bt_dict_producer out{buf.data(), buf.size()};
                handle_monitor_message_single(l.consume_dict_consumer(), out, subs);
                result.append(out.view());
            }
            result += 'e';
        }
    } catch (const std::exception& e) {
        message.send_reply(oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error", "Invalid arguments: Failed to parse monitor.messages data value"}}));
        return;
    }

    if (!subs.empty()) {
        std::unique_lock lock{monitoring_mutex_};
        for (auto& [pubkey, pubkey_hex, namespaces, want_data] : subs) {
            bool found = false;
            for (auto [it, end] = monitoring_.equal_range(pubkey); it != end; ++it) {
                auto& mon_data = it->second;
                if (mon_data.push_conn == message.conn) {
                    mon_data.namespaces =
                            merge_namespaces(std::move(mon_data.namespaces), std::move(namespaces));
                    log::debug(
                            logcat,
                            "monitor.messages sub renewed for {} monitoring namespace(s) {}",
                            pubkey_hex,
                            fmt::join(mon_data.namespaces, ", "));
                    mon_data.reset_expiry();
                    mon_data.want_data |= want_data;
                    found = true;
                    break;
                }
            }
            if (!found) {
                log::debug(
                        logcat,
                        "monitor.messages new subscription for {} monitoring namespace(s) {}",
                        pubkey_hex,
                        fmt::join(namespaces, ", "));
                monitoring_.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(std::move(pubkey)),
                        std::forward_as_tuple(std::move(namespaces), message.conn, want_data));
            }
        }
    }
    message.send_reply(result);
}

static void write_metadata(
        oxenc::bt_dict_producer& d, std::string_view pubkey, const message& msg) {
    d.append("@", pubkey);
    d.append("h", msg.hash);
    d.append("n", to_int(msg.msg_namespace));
    d.append("t", to_epoch_ms(msg.timestamp));
    d.append("z", to_epoch_ms(msg.expiry));
}

void OMQ::send_notifies(message msg) {
    auto pubkey = msg.pubkey.prefixed_raw();
    auto now = std::chrono::steady_clock::now();
    std::vector<oxenmq::ConnectionID> relay_to, relay_to_with_data;
    {
        std::shared_lock lock{monitoring_mutex_};
        for (auto [it, end] = monitoring_.equal_range(pubkey); it != end; ++it) {
            const auto& mon_data = it->second;
            if (mon_data.expiry >= now &&
                std::binary_search(
                        mon_data.namespaces.begin(), mon_data.namespaces.end(), msg.msg_namespace))
                (mon_data.want_data ? relay_to_with_data : relay_to).push_back(mon_data.push_conn);
        }
    }

    if (relay_to.empty() && relay_to_with_data.empty())
        return;

    // We output a dict with keys (in order):
    // - @ pubkey
    // - h msg hash
    // - n msg namespace
    // - t msg timestamp
    // - z msg expiry
    // - ~ msg data (optional)
    constexpr size_t metadata_size = 2       // d...e
                                   + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                   + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                   + 3 + 8   // 1:n and i-32768e
                                   + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                   + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                   + 10;     // safety margin

    oxenc::bt_dict_producer d;
    d.reserve(
            relay_to_with_data.empty() ? metadata_size
                                       : metadata_size  // all the metadata above
                                                 + 3    // 1:~
                                                 + 8    // 76800: plus a couple bytes to grow
                                                 + msg.data.size());

    write_metadata(d, pubkey, msg);

    if (!relay_to.empty())
        for (const auto& conn : relay_to)
            omq_.send(conn, "notify.message", d.view());

    if (!relay_to_with_data.empty()) {
        d.append("~", msg.data);
        for (const auto& conn : relay_to_with_data)
            omq_.send(conn, "notify.message", d.view());
    }
}

}  // namespace oxen::server
