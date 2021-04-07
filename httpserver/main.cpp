#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "oxend_rpc.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "lmq_server.h"
#include "request_handler.h"

#include <sodium.h>
#include <oxenmq/oxenmq.h>
#include <oxenmq/hex.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <vector>

extern "C" {
#include <sys/types.h>
#include <pwd.h>

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
}

namespace fs = std::filesystem;

#ifdef ENABLE_SYSTEMD
static void systemd_watchdog_tick(boost::asio::steady_timer& timer,
                                  const oxen::ServiceNode& sn) {
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

    oxen::command_line_parser parser;

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
        std::cout << STORAGE_SERVER_VERSION_INFO;
        return EXIT_SUCCESS;
    }

    if (options.data_dir.empty()) {
        if (auto home_dir = util::get_home_dir()) {
            if (options.testnet) {
                options.data_dir =
                    (*home_dir / ".oxen" / "testnet" / "storage").u8string();
            } else {
                options.data_dir = (*home_dir / ".oxen" / "storage").u8string();
            }
        }
    }

    if (!fs::exists(options.data_dir)) {
        fs::create_directories(options.data_dir);
    }

    oxen::LogLevel log_level;
    if (!oxen::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        oxen::print_log_levels();
        return EXIT_FAILURE;
    }

    oxen::init_logging(options.data_dir, log_level);

    if (options.testnet) {
        oxen::set_testnet();
        OXEN_LOG(warn,
                 "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    OXEN_LOG(info, "{}", STORAGE_SERVER_VERSION_INFO);

    if (options.ip == "127.0.0.1") {
        OXEN_LOG(critical,
                 "Tried to bind oxen-storage to localhost, please bind "
                 "to outward facing address");
        return EXIT_FAILURE;
    }

    OXEN_LOG(info, "Setting log level to {}", options.log_level);
    OXEN_LOG(info, "Setting database location to {}", options.data_dir);
    OXEN_LOG(info, "Connecting to oxend @ {}", options.oxend_omq_rpc);
    OXEN_LOG(info, "HTTPS server is listening at {}:{}", options.ip,
             options.port);
    OXEN_LOG(info, "OxenMQ is listening at {}:{}", options.ip,
             options.lmq_port);

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        OXEN_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        OXEN_LOG(error, "AES-256-GCM is not available on this CPU");
        return EXIT_FAILURE;
    }

    {
        const auto fd_limit = util::get_fd_limit();
        if (fd_limit != -1) {
            OXEN_LOG(debug, "Open file descriptor limit: {}", fd_limit);
        } else {
            OXEN_LOG(debug, "Open descriptor limit: N/A");
        }
    }

    try {


#ifndef INTEGRATION_TEST
        const auto [private_key, private_key_ed25519, private_key_x25519] =
            oxen::get_sn_privkeys(options.oxend_omq_rpc);
#else
        // Normally we request the key from daemon, but in integrations/swarm
        // testing we are not able to do that, so we extract the key as a
        // command line option:
        const auto private_key = oxen::oxendKeyFromHex(options.oxend_key);
        OXEN_LOG(info, "OXEND LEGACY KEY: {}", options.oxend_key);

        const auto private_key_x25519 = oxen::oxendKeyFromHex(options.oxend_x25519_key);
        OXEN_LOG(info, "x25519 SECRET KEY: {}", options.oxend_x25519_key);

        // Unused at the moment:
        const auto private_key_ed25519 =
            oxen::private_key_ed25519_t::from_hex(options.oxend_ed25519_key);
        OXEN_LOG(info, "ed25519 SECRET KEY: {}", options.oxend_ed25519_key);
#endif

        const auto public_key = oxen::derive_pubkey_legacy(private_key);
        OXEN_LOG(info, "Retrieved keys from Lokid; our SN pubkey is: {}",
                 oxenmq::to_hex(public_key.begin(), public_key.end()));

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key_x25519.begin(),
                                        private_key_x25519.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        oxen::oxend_key_pair_t oxend_key_pair{private_key, public_key};

        const auto public_key_x25519 =
            oxen::derive_pubkey_x25519(private_key_x25519);

        OXEN_LOG(info, "SN x25519 pubkey is: {}", oxenmq::to_hex(
                    public_key_x25519.begin(), public_key_x25519.end()));

        const auto public_key_ed25519 =
            oxen::derive_pubkey_ed25519(private_key_ed25519);

        const std::string pubkey_ed25519_hex = oxenmq::to_hex(
                public_key_ed25519.begin(), public_key_ed25519.end());

        OXEN_LOG(info, "SN ed25519 pubkey is: {}", pubkey_ed25519_hex);

        oxen::oxend_key_pair_t oxend_key_pair_x25519{private_key_x25519,
                                                     public_key_x25519};

        for (const auto& key : options.stats_access_keys) {
            OXEN_LOG(info, "Stats access key: {}", key);
        }

        // We pass port early because we want to send it in the first ping to
        // Oxend (in ServiceNode's constructor), but don't want to initialize
        // the rest of lmq server before we have a reference to ServiceNode
        oxen::OxenmqServer oxenmq_server{options.lmq_port,
                oxend_key_pair_x25519, options.stats_access_keys};

        // TODO: SN doesn't need oxenmq_server, just the lmq components
        oxen::ServiceNode service_node(ioc, worker_ioc, options.port, options.lmq_port,
                                       oxenmq_server, oxend_key_pair,
                                       pubkey_ed25519_hex, options.data_dir,
                                       options.force_start);

        oxen::RequestHandler request_handler(ioc, service_node, channel_encryption);

        oxenmq_server.init(&service_node, &request_handler,
                oxenmq::address{options.oxend_omq_rpc});

        RateLimiter rate_limiter;

        oxen::Security security(oxend_key_pair, options.data_dir);

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        boost::asio::steady_timer systemd_watchdog_timer(ioc);
        systemd_watchdog_tick(systemd_watchdog_timer, service_node);
#endif

        oxen::http_server::run(ioc, options.ip, options.port, options.data_dir,
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
