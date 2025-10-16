#include <chrono>
#include <exception>
#include <random>
#include <string>
#include <cstdio>

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/context.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/loop.hpp>
#include <oxenc/hex.h>
#include <nlohmann/json.hpp>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>
#include <fmt/format.h>
#include <fmt/ranges.h>

using namespace std::literals;

using namespace oxen::quic;
using namespace oxenc::literals;

bool verbose = false;

int usage(std::string_view argv0, std::string_view err = "") {
    if (!err.empty())
        fmt::print(stderr, "\e[31;1mError: {}\e[0m\n\n", err);

    fmt::print(
            stderr,
            R"(Usage: {} [--verbose|-v] SNODE_PK [SNODE_PK ...]

Performs a storage server quic connectivity test for the given service node(s).  Each SNODE_PK
should be the primary pubkey of the service node; its address will be looked up and a test
request will be made to its advertised IP/port.

By default this outputs one line per tested node, of `PUBKEY: (status)`, where (status) is one of:

- `pass` -- test request succeeded
- `FAIL` -- test request failed to connect
- `NOT FOUND` -- given pubkey does not match any current registered service node
- `NO IP` -- given pubkey matches a service node, but we didn't find a recent proof with IP/port
             contact info

The `--verbose` flag can be given for more details.

)",
            argv0);
    return 1;
}

std::array SEEDS = {
        RemoteAddress{
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"_hex,
                "95.216.33.113",
                uint16_t{20200}},
        RemoteAddress{
                "1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef7f971e88ab144c1a7ce"_hex,
                "37.27.236.229",
                uint16_t{20201}},
        RemoteAddress{
                "1f202f00f4d2d4acc01e20773999a291cf3e3136c325474d159814e06199919f"_hex,
                "172.96.140.124",
                uint16_t{20202}},
        RemoteAddress{
                "1f303f1d7523c46fa5398826740d13282d26b5de90fbae5749442f66afb6d78b"_hex,
                "208.73.207.54",
                uint16_t{20203}},
        RemoteAddress{
                "1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad15a35e16b50c28db7b0"_hex,
                "104.194.8.115",
                uint16_t{20204}},
};

std::mt19937_64 rng{std::random_device{}()};

std::shared_ptr<GNUTLSCreds> client_creds() {
    if (sodium_init())
        throw std::runtime_error{"Failed to initialize libsodium"};

    std::array<unsigned char, 32> pk;
    std::string sk;
    sk.resize(64);
    crypto_sign_ed25519_keypair(pk.data(), reinterpret_cast<unsigned char*>(sk.data()));
    return GNUTLSCreds::make_from_ed_seckey(std::move(sk));
}

const std::shared_ptr<GNUTLSCreds> creds = client_creds();

const auto ALPN = "oxenstorage";

std::unordered_map<std::string, std::optional<RemoteAddress>> fetch_sn_addresses(
        const std::shared_ptr<Endpoint>& ep) {
    std::shuffle(SEEDS.begin(), SEEDS.end(), rng);

    nlohmann::json req{
            {"endpoint", "get_service_nodes"},
            {"params",
             {{"fields",
               {{"service_node_pubkey", true},
                {"pubkey_ed25519", true},
                {"public_ip", true},
                {"storage_lmq_port", true}}}}}};

    std::unordered_map<std::string, std::optional<RemoteAddress>> result;
    for (const auto& seed : SEEDS) {
        if (verbose)
            fmt::print(
                    stderr,
                    "\e[3mFetching service node list from seed {}...\e[0m\n",
                    oxenc::to_hex(seed.view_remote_key().subspan(0, 5)));
        auto c = ep->connect(seed, creds);
        auto s = c->open_stream<BTRequestStream>();
        std::promise<nlohmann::json> sns_prom;
        s->command("oxend_request", req.dump(), [&seed, &sns_prom](message resp) {
            try {
                if (resp.is_error())
                    throw std::runtime_error{"Failed to fetch service node list from seed node"};

                sns_prom.set_value(nlohmann::json::parse(resp.body()));
            } catch (...) {
                sns_prom.set_exception(std::current_exception());
            }
        });

        nlohmann::json sns;
        try {
            sns = sns_prom.get_future().get();
            if (!(sns.is_array() && sns.size() == 2 && sns[0].get<int>() == 200))
                throw std::runtime_error{"An error occured: " + sns.dump()};

            for (const auto& state : sns[1]["result"]["service_node_states"]) {
                auto& addr = result[state["service_node_pubkey"].get<std::string>()];
                auto ip = state["public_ip"].get<std::string>();
                if (ip.empty() || ip == "0.0.0.0")
                    continue;

                addr.emplace(
                        oxenc::from_hex(state["pubkey_ed25519"].get<std::string_view>()),
                        std::move(ip),
                        state["storage_lmq_port"].get<uint16_t>());
            }

            return result;

        } catch (const std::exception& e) {
            fmt::print(stderr, "\e[3mFailed to obtain service node list: {}\e[0m\n", e.what());
            result.clear();
        }
    }

    throw std::runtime_error{"Failed to fetch service node state from any seed node!"};
}

enum class Result { pass, fail, not_found, no_ip };
void print_result(
        const std::string& pubkey,
        Result result,
        const RemoteAddress* addr = nullptr,
        std::chrono::nanoseconds reqtime = 0ns,
        std::vector<std::string> extra = {}) {
    fmt::print(
            "{}: {}\n",
            pubkey,
            result == Result::pass        ? "pass"
            : result == Result::fail      ? "FAIL"
            : result == Result::not_found ? "NOT FOUND"
            : result == Result::no_ip     ? "NO IP"
                                          : "???");

    if (!verbose)
        return;

    if (result == Result::pass || result == Result::fail) {
        assert(addr);
        if (auto ed_pk = oxenc::to_hex(addr->view_remote_key()); ed_pk != pubkey)
            fmt::print(" - pre-Oxen-8 server with Ed25519 pubkey {}\n", ed_pk);
        fmt::print(" - Connection + initial request took {:.1f}ms\n", reqtime.count() * 1e-6);
    }
    for (const auto& e : extra)
        if (!e.empty())
            fmt::print(" - {}\n", e);
    fmt::print("\n");
}

int main(int argc, char* argv[]) {
    std::vector<std::string> pubkeys_hex;

    for (int i = 1; i < argc; i++) {
        std::string arg{argv[i]};

        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
            continue;
        }

        if (!oxenc::is_hex(arg) || arg.size() != 64)
            return usage(
                    argv[0],
                    "Invalid pubkey (" + std::string{arg} + "): expected 64-character hex pubkey");

        pubkeys_hex.push_back(std::move(arg));
    }

    if (pubkeys_hex.empty())
        return usage(argv[0]);

    Loop loop;
    auto ep = Endpoint::endpoint(loop, Address{}, opt::outbound_alpns{ALPN});

    auto remotes = fetch_sn_addresses(ep);

    if (verbose)
        fmt::print("\n");

    std::unordered_set<std::string> pubkeys_seen;
    for (const auto& snpub : pubkeys_hex) {
        if (!pubkeys_seen.insert(snpub).second) {
            if (verbose)
                fmt::print(stderr, "\e[3mIgnoring repeated SN {}\e[0m\n", snpub);
            continue;
        }

        auto it = remotes.find(snpub);
        if (it == remotes.end()) {
            print_result(snpub, Result::not_found);
            continue;
        }
        if (!it->second) {
            print_result(snpub, Result::no_ip);
            continue;
        }

        auto& raddr = *it->second;

        auto started = std::chrono::steady_clock::now();

        std::string label =
                fmt::format("{}…{} @ {}", snpub.substr(0, 8), snpub.substr(61), raddr.to_string());
        if (verbose)
            fmt::print(stderr, "\e[3mTesting {}\e[0m\n\n", label);

        auto c = ep->connect(raddr, creds);
        auto s = c->open_stream<BTRequestStream>();
        std::promise<nlohmann::json> info_prom;
        s->command("info", "", [&info_prom](message resp) {
            try {
                if (resp.timed_out)
                    throw std::runtime_error{"connection timed out"};
                if (resp.is_error())
                    throw std::runtime_error{"request failed"};

                info_prom.set_value(nlohmann::json::parse(resp.body()));
            } catch (...) {
                info_prom.set_exception(std::current_exception());
            }
        });

        std::string ver;
        try {
            auto info = info_prom.get_future().get()[1];
            ver = fmt::format(
                    "v{}, hf {}",
                    fmt::format("{}", fmt::join(info["version"].get<std::vector<int>>(), ".")),
                    fmt::format("{}", fmt::join(info["hf"].get<std::vector<int>>(), ".")));
        } catch (const std::exception& e) {
            print_result(
                    snpub,
                    Result::fail,
                    &raddr,
                    std::chrono::steady_clock::now() - started,
                    {fmt::format("request failed: {}", e.what())});
            continue;
        }

        auto initial_done = std::chrono::steady_clock::now();

        std::string extra;
        if (verbose) {
            // Make a second request before we disconnect so that we can report both the
            // first-request time (including connection overhead) and an already-connected request
            // time.
            std::promise<std::string> extra_prom;
            s->command("info", "", [&extra_prom, &initial_done](message resp) {
                if (resp.timed_out)
                    extra_prom.set_value("Follow-up request timed out!");
                else if (resp.is_error())
                    extra_prom.set_value(fmt::format("Follow-up request failed: {}", resp.body()));
                else {
                    std::chrono::nanoseconds t2 = std::chrono::steady_clock::now() - initial_done;
                    extra_prom.set_value(
                            fmt::format("Follow-up request took {:.1f}ms", t2.count() * 1e-6));
                }
            });
            extra = extra_prom.get_future().get();
        }

        auto initial_elapsed = initial_done - started;
        print_result(
                snpub,
                Result::pass,
                &raddr,
                std::chrono::steady_clock::now() - started,
                {std::move(ver), std::move(extra)});
    }
}
