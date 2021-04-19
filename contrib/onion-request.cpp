// C++ backwards engineered command-line onion routing test tool.
//
// This makes onion requests via storage servers.
//
// It has a whole bunch of deps (cpr, oxenmq, sodium, ssl, nlohmann); I compiled with the following,
// using static cpr from an oxen-core build, SS assets built in ../build, and system-installed
// libsodium/libssl/nlohmann/oxenmq:
//
//     g++ -std=c++17 -O2 onion-request.cpp ../../oxen-core/build/external/libcpr.a \
//          -loxenmq -lsodium -lcurl ../build/crypto/libcrypto.a -lcrypto
//

#include "../crypto/include/channel_encryption.hpp"
#include "cpr/cpr.h"
#include "oxenmq/base64.h"
#include <exception>
#include <sodium.h>
#include <oxenmq/hex.h>
#include <oxenmq/oxenmq.h>
#include <iostream>
#include <nlohmann/json.hpp>

extern "C" {
#include <sys/param.h>
}

using namespace oxen;

int usage(const char* argv0) {
    std::cerr << "Usage: " << argv0 << " [--mainnet] SNODE_PK [SNODE_PK ...] -- sends an onion request via the given path\n"
       << "    SNODE_PK should be primary (legacy) pubkey(s)\n";
    return 1;
}

const oxenmq::address TESTNET_OMQ{"tcp://public.loki.foundation:9999"};
const oxenmq::address MAINNET_OMQ{"tcp://public.loki.foundation:22029"};

void onion_request(std::string ip, uint16_t port, std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys, bool mainnet);

int main(int argc, char** argv) {
    std::vector<std::string_view> pubkeys_hex;
    std::vector<legacy_pubkey> pubkeys;
    auto omq_addr = TESTNET_OMQ;
    for (int i = 1; i < argc; i++) {
        if (argv[i] == "--mainnet"sv) {
            omq_addr = MAINNET_OMQ;
            continue;
        }
        auto pk = pubkeys_hex.emplace_back(argv[i]);
        if (pk.size() != 64 || !oxenmq::is_hex(pk)) {
            std::cerr << "Invalid pubkey '" << pk << "'\n";
            return usage(argv[0]);
        }
        pubkeys.push_back(legacy_pubkey::from_hex(pk));
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
                if (e.size() != 64 || x.size() != 64 || !oxenmq::is_hex(x) || !oxenmq::is_hex(e))
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
                std::cerr << pk << " is not an active SN\n";
        }
        if (chain.size() != pubkeys.size()) throw std::runtime_error{"Missing x25519 pubkeys"};
        if (chain.size() < 2) throw std::runtime_error{"Need at least two pubkeys"};

        if (first_ip.empty() || !first_port)
            throw std::runtime_error{"Missing IP/port of first hop"};

        onion_request(first_ip, first_port, std::move(chain), omq_addr == MAINNET_OMQ);

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

void onion_request(std::string ip, uint16_t port, std::vector<std::pair<ed25519_pubkey, x25519_pubkey>> keys, bool mainnet) {
    std::string_view user_pubkey = "05fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    if (!mainnet) user_pubkey.remove_prefix(2);

    std::string blob;

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
    //   (though "target" must start with /loki/ or /oxen/ and end with /lsrpc).
    // - "destination" and "ephemeral_key" to forward the request to the next hop.
    //
    // This later case continues onion routing by giving us something like:
    //
    //      {"destination":"ed25519pubkey","ephemeral_key":"x25519-eph-pubkey-for-decryption"}
    //
    // and we forward this via oxenmq to the given ed25519pubkey (but since oxenmq uses x25519
    // pubkeys we first have to go look it up), sending:
    //
    //      [sn.onion_req_v2][eph-key][BLOB]
    //
    // where BLOB is the opaque data received from the previous hop.  That next hop decrypts BLOB,
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

    auto it = keys.rbegin();
    {
        crypto_box_keypair(A.data(), a.data());
        oxen::ChannelEncryption e{a};
        auto payload = nlohmann::json{
            {"method", "get_snodes_for_pubkey"},
            {"params", {
                {"pubKey", user_pubkey},
                {"foobar", true},
            }}
        }.dump();
        auto data = encode_size(payload.size()) + payload +
            nlohmann::json{{"headers", std::array<int, 0>{}},}.dump();
        blob = e.encrypt(EncryptType::aes_gcm, data, keys.back().second);
        final_seckey = a;
        final_pubkey = A;
    }

    for (it++; it != keys.rend(); it++) {
        // Routing data for this hop:
        nlohmann::json routing{
            {"destination", it->first.hex()}, // Next hop's ed25519 key
            {"foobar", "fedcba"},
            {"ephemeral_key", A.hex()}}; // The x25519 ephemeral_key here is the key for the *next* hop to use

        blob = encode_size(blob.size()) + blob + routing.dump();

        // Generate eph key for *this* request and encrypt it:
        crypto_box_keypair(A.data(), a.data());
        oxen::ChannelEncryption e{a};

        blob = e.encrypt(EncryptType::aes_gcm, blob, it->second);

        if (std::next(it) == keys.rend()) {
            // This is the first hop, so have to add one more layer to tell the first hop how to
            // decrypt the initial payload:
            blob = encode_size(blob.size()) + blob +
                nlohmann::json{{"ephemeral_key", A.hex()}}.dump();
        }
    }

    cpr::Url target{"https://" + ip + ":" + std::to_string(port) + "/onion_req/v2"};
    std::cout << "Posting to " << target.str() << " for entry node\n";
    auto res = cpr::Post(target,
            cpr::Body{blob},
            cpr::VerifySsl{false});

    std::cout << "Got " << res.status_line << " response\n";
    if (!res.raw_header.empty())
        std::cout << "Headers:\n" << res.raw_header << "\n\n";

    if (!oxenmq::is_base64(res.text)) {
        std::cout << "Body (" << res.text.size() << " bytes):\n" << res.text << "\n";
    } else {
        auto body = oxenmq::from_base64(res.text);
        std::cout << "Body is " << res.text.size() << " base64 bytes for " << body.size() << " bytes of data\n";
        oxen::ChannelEncryption d{final_seckey};
        try {
            body = d.decrypt(EncryptType::aes_gcm, body, keys.back().second);

            std::cout << "Body decrypted to " << body.size() << " bytes:\n" << body << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Decryption failed: " << e.what() << "\n";
        }
    }
}
