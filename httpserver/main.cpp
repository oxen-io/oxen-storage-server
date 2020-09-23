#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "loki_logger.h"
#include "lokid_key.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "lmq_server.h"
#include "request_handler.h"

#include <boost/filesystem.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <vector>

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

namespace fs = boost::filesystem;

static std::optional<fs::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifdef WIN32
    return std::nullopt;
#endif

    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        return std::nullopt;

    return fs::path(pszHome);
}

#ifdef ENABLE_SYSTEMD
static void systemd_watchdog_tick(boost::asio::steady_timer& timer,
                                  const loki::ServiceNode& sn) {
    using namespace std::literals;
    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + sn.get_status_line()).c_str());
    timer.expires_after(10s);
    timer.async_wait([&](const boost::system::error_code&) {
        systemd_watchdog_tick(timer, sn);
    });
}
#endif

constexpr int EXIT_INVALID_PORT = 2;

int main(int argc, char* argv[]) {

    loki::command_line_parser parser;

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        parser.print_usage();
        return EXIT_FAILURE;
    }

    auto options = parser.get_options();

    if (options.print_help) {
        parser.print_usage();
        return EXIT_SUCCESS;
    }

    if (options.print_version) {
        std::cout << version_info();
        return EXIT_SUCCESS;
    }

    if (options.data_dir.empty()) {
        if (auto home_dir = get_home_dir()) {
            if (options.testnet) {
                options.data_dir =
                    (*home_dir / ".loki" / "testnet" / "storage").string();
            } else {
                options.data_dir = (*home_dir / ".loki" / "storage").string();
            }
        }
    }

    if (!fs::exists(options.data_dir)) {
        fs::create_directories(options.data_dir);
    }

    loki::LogLevel log_level;
    if (!loki::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        loki::print_log_levels();
        return EXIT_FAILURE;
    }

    loki::init_logging(options.data_dir, log_level);

    if (options.testnet) {
        loki::set_testnet();
        LOKI_LOG(warn,
                 "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    print_version();

    if (options.ip == "127.0.0.1") {
        LOKI_LOG(critical,
                 "Tried to bind loki-storage to localhost, please bind "
                 "to outward facing address");
        return EXIT_FAILURE;
    }

    if (options.port == options.lokid_rpc_port) {
        LOKI_LOG(error, "Storage server port must be different from that of "
                        "Lokid! Terminating.");
        exit(EXIT_INVALID_PORT);
    }

    LOKI_LOG(info, "Setting log level to {}", options.log_level);
    LOKI_LOG(info, "Setting database location to {}", options.data_dir);
    LOKI_LOG(info, "Setting Lokid RPC to {}:{}", options.lokid_rpc_ip,
             options.lokid_rpc_port);
    LOKI_LOG(info, "Https server is listening at {}:{}", options.ip,
             options.port);
    LOKI_LOG(info, "LokiMQ is listening at {}:{}", options.ip,
             options.lmq_port);

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        LOKI_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        LOKI_LOG(error, "AES-256-GCM is not available on this CPU");
        return EXIT_FAILURE;
    }

    {
        const auto fd_limit = util::get_fd_limit();
        if (fd_limit != -1) {
            LOKI_LOG(debug, "Open file descriptor limit: {}", fd_limit);
        } else {
            LOKI_LOG(debug, "Open descriptor limit: N/A");
        }
    }

    try {

        auto lokid_client = loki::LokidClient(ioc, options.lokid_rpc_ip,
                                              options.lokid_rpc_port);

        // Normally we request the key from daemon, but in integrations/swarm
        // testing we are not able to do that, so we extract the key as a
        // command line option:
        loki::private_key_t private_key;
        loki::private_key_ed25519_t private_key_ed25519; // Unused at the moment
        loki::private_key_t private_key_x25519;
#ifndef INTEGRATION_TEST
        std::tie(private_key, private_key_ed25519, private_key_x25519) =
            lokid_client.wait_for_privkey();
#else
        private_key = loki::lokidKeyFromHex(options.lokid_key);
        LOKI_LOG(info, "LOKID LEGACY KEY: {}", options.lokid_key);

        private_key_x25519 = loki::lokidKeyFromHex(options.lokid_x25519_key);
        LOKI_LOG(info, "x25519 SECRET KEY: {}", options.lokid_x25519_key);

        private_key_ed25519 =
            loki::private_key_ed25519_t::from_hex(options.lokid_ed25519_key);

        LOKI_LOG(info, "ed25519 SECRET KEY: {}", options.lokid_ed25519_key);
#endif

        const auto public_key = loki::derive_pubkey_legacy(private_key);
        LOKI_LOG(info, "Retrieved keys from Lokid; our SN pubkey is: {}",
                 util::as_hex(public_key));

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key_x25519.begin(),
                                        private_key_x25519.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        loki::lokid_key_pair_t lokid_key_pair{private_key, public_key};

        const auto public_key_x25519 =
            loki::derive_pubkey_x25519(private_key_x25519);

        LOKI_LOG(info, "SN x25519 pubkey is: {}",
                 util::as_hex(public_key_x25519));

        const auto public_key_ed25519 =
            loki::derive_pubkey_ed25519(private_key_ed25519);

        const std::string pubkey_ed25519_hex = util::as_hex(public_key_ed25519);

        LOKI_LOG(info, "SN ed25519 pubkey is: {}", pubkey_ed25519_hex);

        loki::lokid_key_pair_t lokid_key_pair_x25519{private_key_x25519,
                                                     public_key_x25519};

        LOKI_LOG(info, "Stats access key: {}", options.stats_access_key);

        // We pass port early because we want to send it in the first ping to
        // Lokid (in ServiceNode's constructor), but don't want to initialize
        // the rest of lmq server before we have a reference to ServiceNode
        loki::LokimqServer lokimq_server(options.lmq_port);

        // TODO: SN doesn't need lokimq_server, just the lmq components
        loki::ServiceNode service_node(ioc, worker_ioc, options.port,
                                       lokimq_server, lokid_key_pair,
                                       pubkey_ed25519_hex, options.data_dir,
                                       lokid_client, options.force_start);

        loki::RequestHandler request_handler(ioc, service_node, lokid_client,
                                             channel_encryption);

        lokimq_server.init(&service_node, &request_handler,
                           lokid_key_pair_x25519, options.stats_access_key);

        RateLimiter rate_limiter;

        loki::Security security(lokid_key_pair, options.data_dir);

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        boost::asio::steady_timer systemd_watchdog_timer(ioc);
        systemd_watchdog_tick(systemd_watchdog_timer, service_node);
#endif

        loki::http_server::run(ioc, options.ip, options.port, options.data_dir,
                               service_node, request_handler, rate_limiter,
                               security);
    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        std::cerr << "Exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown exception caught in main." << std::endl;
        return EXIT_FAILURE;
    }
}
