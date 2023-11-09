// C++ backwards engineered command-line onion routing test tool.
//
// This makes onion requests via storage servers.
//
// It has a whole bunch of deps (cpr, oxenmq, sodium, ssl, nlohmann); I compiled with the following,
// using static cpr from an oxen-core build, SS assets built in ../build, and system-installed
// libsodium/libssl/nlohmann/oxenmq:
//
//     g++ -std=c++17 -O2 onion-request.cpp -o onion-request ../../oxen-core/build/external/libcpr.a \
//          -I../../oxen-core/external/cpr/include ../build/crypto/libcrypto.a -loxenmq -lsodium -lcurl -lcrypto
//

#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>
#include <cpr/cpr.h>
#include <chrono>
#include <exception>
#include <iostream>
#include <random>
#include <sodium.h>
#include <oxenc/hex.h>
#include <oxenc/base64.h>
#include <oxenmq/oxenmq.h>
#include <nlohmann/json.hpp>

extern "C" {
#include <sys/param.h>
}

using namespace std::literals;

using namespace oxenss;
using namespace oxenss::crypto;

int usage(std::string_view argv0, std::string_view err = "") {
    if (!err.empty())
        std::cerr << "\x1b[31;1mError: " << err << "\x1b[0m\n\n";
    std::cerr << "Usage: " << argv0 << R"( [--mainnet] [--xchacha20|--aes-gcm|--aes-cbc|--random] SNODE_PK [SNODE_PK ...] PAYLOAD CONTROL

Sends an onion request via the given path

SNODE_PK should be primary (legacy) pubkey(s) on test (or mainnet if --mainnet is given).

--xchacha20 uses xchacha20+poly1305 encryption (which is the default);
--aes-gcm and --aes-cbc use aes-gcm and aes-cbc, respectively, instead.
--random uses a random encryption type for each hop.

PAYLOAD/CONTROL are values to pass to the request and should be:

Onion requests for SS and oxend:

    Pass '{"headers":[]}' for CONTROL

    PAYLOAD should be the JSON data; for example for an oxend request:

        {"method": "oxend_request", "params": {"endpoint": "get_service_nodes", "params": {"limit": 5}}}

    and for a swarm member lookup:

        {"method": "get_snodes_for_pubkey", {"params": {"pubKey": user_pubkey}}}

Proxy requests should have an whatever data is to be posted in the PAYLOAD string and CONTROL set to
the connection details such as:

        {"host": "jagerman.com", "target": "/oxen/lsrpc"}

Both PAYLOAD and CONTROL may be passed filenames to read prefixed with `@` (for example:
@payload.data, @/path/to/control.json)

)";
    return 1;
}

const oxenmq::address TESTNET_OMQ{"tcp://public.loki.foundation:9999"};
const oxenmq::address MAINNET_OMQ{"tcp://public.loki.foundation:22029"};

void onion_request(std::string ip, uint16_t port, std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys,
        std::optional<EncryptType> enc_type, std::string_view payload, std::string_view control);

int main(int argc, char** argv) {
    std::vector<std::string_view> pubkeys_hex;
    std::vector<legacy_pubkey> pubkeys;
    auto omq_addr = TESTNET_OMQ;
    std::optional<EncryptType> enc_type = EncryptType::xchacha20;
    std::string payload, control;
    for (int i = 1; i < argc; i++) {
        std::string_view arg{argv[i]};
        if (arg == "--mainnet"sv) { omq_addr = MAINNET_OMQ; continue; }
        if (arg == "--testnet"sv) { omq_addr = TESTNET_OMQ; continue; }
        if (arg == "--xchacha20"sv) { enc_type = EncryptType::xchacha20; continue; }
        if (arg == "--aes-gcm"sv) { enc_type = EncryptType::aes_gcm; continue; }
        if (arg == "--aes-cbc"sv) { enc_type = EncryptType::aes_cbc; continue; }
        if (arg == "--random"sv) { enc_type = std::nullopt; continue; }

        bool hex = arg.size() > 0 && oxenc::is_hex(arg);
        if (i >= argc - 2) {
            if (hex)
                return usage(argv[0], "Missing PAYLOAD and CONTROL values");

            // Could parse control to make sure it's valid json here, but it can be useful to
            // deliberate send invalid json for testing purposes to see how the remote handles it.
            auto& var = (i == argc - 2 ? payload : control);
            var = arg;
            if (!var.empty() && var.front() == '@') {
                std::ifstream f;
                f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
                f.open(var.data()+1, std::ios::in | std::ios::binary);
                var.clear();
                var.append(std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{});
            }
        } else {
            if (!(hex && arg.size() == 64))
                return usage(argv[0], "Invalid pubkey '" + std::string{arg} + "'");
            pubkeys_hex.push_back(arg);
            pubkeys.push_back(legacy_pubkey::from_hex(arg));
        }
    }
    if (pubkeys.empty()) return usage(argv[0]);

    oxenmq::OxenMQ omq{};
    omq.start();
    std::promise<void> got;
    auto got_fut = got.get_future();
    auto rpc = omq.connect_remote(omq_addr,
            [](auto) {},
            [&got, omq_addr](auto, auto err) {
                try { throw std::runtime_error{"Failed to connect to oxend @ " + omq_addr.full_address() + ": " + std::string{err}}; }
                catch (...) { got.set_exception(std::current_exception()); }
            });
    std::string first_ip;
    uint16_t first_port = 0;
    std::unordered_map<legacy_pubkey, std::pair<ed25519_pubkey, x25519_pubkey>> aux_keys;
    omq.request(rpc, "rpc.get_service_nodes", [&](bool success, std::vector<std::string> data) {
        try {
            if (!success || data[0] != "200")
                throw std::runtime_error{"get_service_nodes request failed: " + data[0]};

            auto json = nlohmann::json::parse(data[1]);
            auto sns = json.at("service_node_states");
            for (auto& sn : sns) {
                auto& pk = sn.at("service_node_pubkey").get_ref<const std::string&>();
                auto& e = sn.at("pubkey_ed25519").get_ref<const std::string&>();
                auto& x = sn.at("pubkey_x25519").get_ref<const std::string&>();
                if (e.size() != 64 || x.size() != 64 || !oxenc::is_hex(x) || !oxenc::is_hex(e))
                    throw std::runtime_error{sn.at("service_node_pubkey").get<std::string>() + " is missing ed/x25519 pubkeys"};
                aux_keys.emplace(legacy_pubkey::from_hex(pk),
                        std::make_pair(ed25519_pubkey::from_hex(e), x25519_pubkey::from_hex(x)));
                if (pk == pubkeys_hex.front()) {
                    first_ip = sn.at("public_ip").get<std::string>();
                    first_port = sn.at("storage_port").get<uint16_t>();
                }
            }
            got.set_value();
        }
        catch (...) { got.set_exception(std::current_exception()); }
    }, nlohmann::json{
            {"service_node_pubkeys", pubkeys_hex},
            {"fields", {
               {"service_node_pubkey", true},
               {"pubkey_x25519", true},
               {"pubkey_ed25519", true},
               {"public_ip", true},
               {"storage_port", true},
            }},
            {"active_only", true},
        }.dump()
    );

    try {
        got_fut.get();
        std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> chain;
        for (auto& pk : pubkeys) {
            if (auto it = aux_keys.find(pk); it != aux_keys.end())
                chain.push_back(it->second);
            else
                std::cerr << pk.hex() << " is not an active SN\n";
        }
        if (chain.size() != pubkeys.size()) throw std::runtime_error{"Missing x25519 pubkeys"};
        if (chain.empty()) throw std::runtime_error{"Need at least one SN pubkey"};

        if (first_ip.empty() || !first_port)
            throw std::runtime_error{"Missing IP/port of first hop"};

        onion_request(first_ip, first_port, std::move(chain), enc_type, payload, control);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what();
        return 2;
    }
}

std::string encode_size(uint32_t s) {
    std::string str{reinterpret_cast<const char*>(&s), 4};
#if __BYTE_ORDER == __BIG_ENDIAN
    std::swap(str[0], str[3]);
    std::swap(str[1], str[2]);
#elif __BYTE_ORDER != __LITTLE_ENDIAN
#error Unknown endianness
#endif
    return str;
}

static std::mt19937_64 rng{std::random_device{}()};
EncryptType random_etype() {
    std::uniform_int_distribution<int> dist{0, 2};
    size_t i = dist(rng);
    return i == 0 ? EncryptType::aes_cbc :
        i == 1 ? EncryptType::aes_gcm :
        EncryptType::xchacha20;
}

void onion_request(std::string ip, uint16_t port, std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys,
        std::optional<EncryptType> enc_type, std::string_view payload, std::string_view control) {
    std::string blob;

    std::cerr << "Building " << (keys.size()-1) << "-hop onion request\n";
    // First hop:
    //
    // [N][ENCRYPTED]{json}
    //
    // where json has the ephemeral_key indicating how we encrypted ENCRYPTED for this first hop.
    // The first hop decrypts ENCRYPTED into:
    //
    // [N][BLOB]{json}
    //
    // where [N] is the length of the blob and {json} now contains either:
    // - a "headers" key with an empty value.  This is how we indicate that the request is for this
    //   node as the final hop, and means that the BLOB is actually JSON it should parse to get the
    //   request info (which has "method", "params", etc. in it).
    // - "host"/"target"/"port"/"protocol" asking for an HTTP or HTTPS proxy request to be made
    //   (though "target" must start with /loki/ or /oxen/ and end with /lsrpc).  (There is still a
    //   blob here, but it is not used and typically empty).
    // - "destination" and "ephemeral_key" to forward the request to the next hop.
    //
    // This later case continues onion routing by giving us something like:
    //
    //      {"destination":"ed25519pubkey","ephemeral_key":"x25519-eph-pubkey-for-decryption","enc_type":"xchacha20"}
    //
    // (enc_type can also be aes-gcm, and defaults to that if not specified).  We forward this via
    // oxenmq to the given ed25519pubkey (but since oxenmq uses x25519 pubkeys we first have to go
    // look it up), sending an oxenmq request to sn.onion_req_v2 of the following (but bencoded, not
    // json):
    //
    //  { "d": "BLOB", "ek": "ephemeral-key-in-binary", "et": "xchacha20", "nh": N }
    //
    // where BLOB is the opaque data received from the previous hop and N is the hop number which
    // gets incremented at each hop (and terminates if it exceeds 15).  That next hop decrypts BLOB,
    // giving it a value interpreted as the same [N][BLOB]{json} as above, and we recurse.
    //
    // On the *return* trip, the message gets encrypted (once!) at the final destination using the
    // derived key from the pubkey given to the final hop, base64-encoded, then passed back without
    // any onion encryption at all all the way back to the client.

    // Ephemeral keypair:
    x25519_pubkey A;
    x25519_seckey a;
    x25519_pubkey final_pubkey;
    x25519_seckey final_seckey;
    EncryptType last_etype;
    EncryptType final_etype;

    auto it = keys.rbegin();
    {
        crypto_box_keypair(A.data(), a.data());
        ChannelEncryption e{a, A, false};

        auto data = encode_size(payload.size());
        data += payload;
        data += control;

        last_etype = final_etype = enc_type.value_or(random_etype());
#ifndef NDEBUG
        std::cerr << "Encrypting for final hop using " << to_string(last_etype) << "/" << A.view() << "\n";
#endif
        blob = e.encrypt(last_etype, data, keys.back().second);
        // Save these because we need them again to decrypt the final response:
        final_seckey = a;
        final_pubkey = A;
    }

    for (it++; it != keys.rend(); it++) {
        // Routing data for this hop:
        nlohmann::json routing{
            {"destination", std::prev(it)->first.hex()}, // Next hop's ed25519 key
            {"ephemeral_key", A.hex()}, // The x25519 ephemeral_key here is the key for the *next* hop to use
            {"enc_type", to_string(last_etype)},
        };

        blob = encode_size(blob.size()) + blob + routing.dump();

        // Generate eph key for *this* request and encrypt it:
        crypto_box_keypair(A.data(), a.data());
        ChannelEncryption e{a, A, false};
        last_etype = enc_type.value_or(random_etype());

#ifndef NDEBUG
        std::cerr << "Encrypting for next-last hop using " << to_string(last_etype) << "/" << A.view() << "\n";
#endif
        blob = e.encrypt(last_etype, blob, it->second);
    }

    // The data going to the first hop needs to be wrapped in one more layer to tell the first hop
    // how to decrypt the initial payload:
    blob = encode_size(blob.size()) + blob + nlohmann::json{
        {"ephemeral_key", A.hex()}, {"enc_type", to_string(last_etype)}}.dump();

    cpr::Url target{"https://" + ip + ":" + std::to_string(port) + "/onion_req/v2"};
    std::cerr << "Posting " << blob.size() << " onion blob to " << target.str() << " for entry node\n";
    auto started = std::chrono::steady_clock::now();
    auto res = cpr::Post(target,
            cpr::Body{blob},
            cpr::VerifySsl{false});
    auto finished = std::chrono::steady_clock::now();

    std::cerr << "Got '" << res.status_line << "' onion request response in " <<
        std::chrono::duration<double>(finished - started).count() << "s\n";
    for (auto& [k, v] : res.header)
        std::cerr << "- " << k << ": " << v << "\n";

    if (res.text.empty()) {
        std::cerr << "Request returned empty body\n";
        return;
    }

    // Nothing in the response tells us how it is encoded so we have to guess; the client normally
    // *does* know because it specifies `"base64": false` if it wants binary, but I don't want to
    // parse and guess what we should do, so we'll just guess.
    ChannelEncryption d{final_seckey, final_pubkey, false};
    bool decrypted = false;
    auto body = std::move(res.text);
    auto orig_size = body.size();
    try { body = d.decrypt(final_etype, body, keys.back().second); decrypted = true; }
    catch (...) {}

    if (decrypted) {
        std::cerr << "Body is " << orig_size << " encrypted bytes, decrypted to " << body.size() << " bytes:\n";
    } else if (oxenc::is_base64(body)) {
        body = oxenc::from_base64(body);
        std::cerr << "Body was " << orig_size << " base64 bytes; decoded to " << body.size() << " bytes";
        try { body = d.decrypt(final_etype, body, keys.back().second); decrypted = true; }
        catch (...) {}
        if (decrypted)
            std::cerr << "; decrypted to " << body.size() << " bytes:\n";
        else
            std::cerr << "; not encrypted (or decryption failed)\n";
    } else {
        std::cerr << "Body is " << body.size() << " bytes (not base64-encoded, not encrypted [or decryption failed])\n";
    }
    std::cerr << std::flush;

    std::cout << body;
    if (!body.empty() && body.back() != '\n')
        std::cout << '\n';
}
