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

    void monitor_error(oxenmq::Message& m, MonitorResponse r, std::string_view message) {
        std::string buf;
        buf.resize(message.size() + 30);
        oxenc::bt_dict_producer d{buf.data(), buf.size()};
        d.append("errcode", static_cast<std::underlying_type_t<MonitorResponse>>(r));
        d.append("error", message);
        buf.resize(d.view().size());
        m.send_reply(buf);
    }

}  // namespace

void OMQ::handle_monitor_messages(oxenmq::Message& message) {
    if (message.data.size() != 1)
        return monitor_error(
                message,
                MonitorResponse::BAD_ARGS,
                "Invalid arguments: monitor.messages takes a single bencoded dict parameter");
    const auto& m = message.data[0];
    if (m.size() < 2 || m.front() != 'd')
        return monitor_error(
                message,
                MonitorResponse::BAD_ARGS,
                "Invalid arguments: monitor.messages parameter must be a bencoded dict");
    oxenc::bt_dict_consumer d{m};

    // Values we receive, in bt-dict order:
    std::string_view ed_pk;   // P
    std::string_view subkey;  // S
    bool want_data = false;   // d
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
                        message,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided P= Session Ed25519 pubkey must be 32 bytes");
        }

        // Subkey for subkey auth (optional)
        if (d.skip_until("S")) {
            subkey = d.consume_string_view();
            if (subkey.size() != 32)
                return monitor_error(
                        message,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided S= subkey must be 32 bytes");
        }

        // Send full data (optional)
        if (d.skip_until("d"))
            want_data = d.consume_integer<bool>();

        // List of namespaces to monitor (required)
        if (d.skip_until("n")) {
            auto ns = d.consume_list_consumer();
            namespaces.push_back(static_cast<namespace_id>(ns.consume_integer<namespace_int>()));
            while (!ns.is_finished()) {
                auto nsi = static_cast<namespace_id>(ns.consume_integer<namespace_int>());
                if (nsi > namespaces.back())
                    namespaces.push_back(nsi);
                else
                    return monitor_error(
                            message,
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
                        message,
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
                    message, MonitorResponse::BAD_SIG, "Provided s= signature must be 64 bytes");

        if (!d.skip_until("t"))
            throw std::runtime_error{"required signature timestamp is missing"};
        timestamp = std::chrono::seconds{d.consume_integer<int64_t>()};

    } catch (const std::exception& ex) {
        return monitor_error(
                message,
                MonitorResponse::BAD_ARGS,
                fmt::format("Invalid arguments: invalid {}= value: {}", d.key(), ex.what()));
    }

    // Make sure the sig timestamp isn't too old or too new
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::time_point(timestamp);
    if (bool too_old = ts < now - 14 * 24h; too_old || ts > now + 24h) {
        return monitor_error(
                message,
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
                    message, MonitorResponse::BAD_PUBKEY, "Invalid P= ed25519 public key");
    } else {
        // No Session Ed25519, so assume the pubkey (without prefix byte) is Ed25519
        ed_pk = pubkey;
        ed_pk.remove_prefix(1);
    }

    std::string_view verify_key = ed_pk;
    std::array<unsigned char, 32> subkey_pub;
    if (!subkey.empty()) {
        try {
            subkey_pub = crypto::subkey_verify_key(ed_pk, subkey);
        } catch (const std::invalid_argument& ex) {
            auto m = fmt::format("Signature verification failed: {}", ex.what());
            log::warning(logcat, "{}", m);
            return monitor_error(message, MonitorResponse::BAD_SIG, m);
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
        return monitor_error(message, MonitorResponse::BAD_SIG, "Signature verification failed");
    }

    {
        std::unique_lock lock{monitoring_mutex_};
        bool found = false;
        for (auto [it, end] = monitoring_.equal_range(pubkey); it != end; ++it) {
            auto& mon_data = it->second;
            if (mon_data.push_conn == message.conn) {
                log::debug(
                        logcat,
                        "monitor.messages subscription renewed for {} monitoring namespace(s) {}",
                        pubkey_hex,
                        fmt::join(namespaces, ", "));
                mon_data.reset_expiry();
                mon_data.namespaces = std::move(namespaces);
                mon_data.want_data = want_data;
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
                    std::forward_as_tuple(pubkey),
                    std::forward_as_tuple(std::move(namespaces), message.conn, want_data));
        }
    }

    message.send_reply("d7:successi1ee");
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
    // - ~d msg data (optional)
    constexpr size_t metadata_size = 2       // d...e
                                   + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                   + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                   + 3 + 8   // 1:n and i-32768e
                                   + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                   + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                   + 10;     // safety margin

    std::string data;
    if (!relay_to_with_data.empty())
        data.resize(
                metadata_size  // all the metadata above
                + 3            // 1:~
                + 8            // 76800: plus a couple bytes to grow
                + msg.data.size());
    else
        data.resize(metadata_size);

    if (!relay_to.empty()) {
        oxenc::bt_dict_producer d{data.data(), data.size()};
        write_metadata(d, pubkey, msg);

        for (const auto& conn : relay_to)
            omq_.send(conn, "notify.message", data);
    }

    if (!relay_to_with_data.empty()) {
        oxenc::bt_dict_producer d{data.data(), data.size()};
        write_metadata(d, pubkey, msg);
        d.append("~", msg.data);

        for (const auto& conn : relay_to_with_data)
            omq_.send(conn, "notify.message", data);
    }
}

}  // namespace oxen::server
