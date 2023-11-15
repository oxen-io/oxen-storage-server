#include "utils.h"

#include <oxenss/crypto/subaccount.h>
#include <oxenss/rpc/request_handler.h>

#include <oxenc/hex.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>

static auto logcat = oxen::log::Cat("utils");

namespace oxenss {

oxenc::bt_value json_to_bt(nlohmann::json j) {
    if (j.is_object()) {
        oxenc::bt_dict res;
        for (auto& [k, v] : j.items())
            res[k] = json_to_bt(v);
        return res;
    }
    if (j.is_array()) {
        oxenc::bt_list res;
        for (auto& v : j)
            res.push_back(json_to_bt(v));
        return res;
    }
    if (j.is_string())
        return j.get<std::string>();
    if (j.is_boolean())
        return j.get<bool>() ? 1 : 0;
    if (j.is_number_unsigned())
        return j.get<uint64_t>();
    if (j.is_number_integer())
        return j.get<int64_t>();

    throw std::runtime_error{
            "client request returned json with an unhandled value type, unable to convert to bt"};
}

nlohmann::json bt_to_json(oxenc::bt_dict_consumer d) {
    nlohmann::json j = nlohmann::json::object();
    while (!d.is_finished()) {
        std::string key{d.key()};
        if (d.is_string())
            j[key] = d.consume_string();
        else if (d.is_dict())
            j[key] = bt_to_json(d.consume_dict_consumer());
        else if (d.is_list())
            j[key] = bt_to_json(d.consume_list_consumer());
        else if (d.is_negative_integer())
            j[key] = d.consume_integer<int64_t>();
        else if (d.is_integer())
            j[key] = d.consume_integer<uint64_t>();
        else
            assert(!"invalid bt type!");
    }
    return j;
}

nlohmann::json bt_to_json(oxenc::bt_list_consumer l) {
    nlohmann::json j = nlohmann::json::array();
    while (!l.is_finished()) {
        if (l.is_string())
            j.push_back(l.consume_string());
        else if (l.is_dict())
            j.push_back(bt_to_json(l.consume_dict_consumer()));
        else if (l.is_list())
            j.push_back(bt_to_json(l.consume_list_consumer()));
        else if (l.is_negative_integer())
            j.push_back(l.consume_integer<int64_t>());
        else if (l.is_integer())
            j.push_back(l.consume_integer<uint64_t>());
        else
            assert(!"invalid bt type!");
    }
    return j;
}

void handle_monitor_message_single(
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

void handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<sub_info>& subs) {
    handle_monitor_message_single(d, out, subs);
}

std::string encode_onion_data(std::string_view payload, const rpc::OnionRequestMetadata& data) {
    return oxenc::bt_serialize<oxenc::bt_dict>({
            {"data", payload},
            {"enc_type", to_string(data.enc_type)},
            {"ephemeral_key", data.ephem_key.view()},
            {"hop_no", data.hop_no},
    });
}

std::pair<std::string_view, rpc::OnionRequestMetadata> decode_onion_data(std::string_view data) {
    // NB: stream parsing here is alphabetical (that's also why these keys *aren't* constexprs:
    // that would potentially be error-prone if someone changed them without noticing the sort
    // order requirements).
    std::pair<std::string_view, rpc::OnionRequestMetadata> result;
    auto& [payload, meta] = result;
    oxenc::bt_dict_consumer d{data};
    if (!d.skip_until("data"))
        throw std::runtime_error{"required data payload not found"};
    payload = d.consume_string_view();

    if (d.skip_until("enc_type"))
        meta.enc_type = crypto::parse_enc_type(d.consume_string_view());
    else
        meta.enc_type = crypto::EncryptType::aes_gcm;

    if (!d.skip_until("ephemeral_key"))
        throw std::runtime_error{"ephemeral key not found"};
    meta.ephem_key = crypto::x25519_pubkey::from_bytes(d.consume_string_view());

    if (d.skip_until("hop_no"))
        meta.hop_no = d.consume_integer<int>();
    if (meta.hop_no < 1)
        meta.hop_no = 1;

    return result;
}

}  // namespace oxenss
