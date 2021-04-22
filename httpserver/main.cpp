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

#include <sodium/core.h>
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
        std::cout << oxen::STORAGE_SERVER_VERSION_INFO;
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
        oxen::is_mainnet = false;
        OXEN_LOG(warn,
                 "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    OXEN_LOG(info, "{}", oxen::STORAGE_SERVER_VERSION_INFO);

#ifdef INTEGRATION_TEST
    OXEN_LOG(warn, "Compiled for integration tests; this binary will not function as a regular storage server!");
#endif

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

    if (sodium_init() != 0) {
        OXEN_LOG(error, "Could not initialize libsodium");
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
        using namespace oxen;

        std::vector<x25519_pubkey> stats_access_keys;
        for (const auto& key : options.stats_access_keys) {
            stats_access_keys.push_back(x25519_pubkey::from_hex(key));
            OXEN_LOG(info, "Stats access key: {}", key);
        }

#ifndef INTEGRATION_TEST
        const auto [private_key, private_key_ed25519, private_key_x25519] =
            get_sn_privkeys(options.oxend_omq_rpc);
#else
        // Normally we request the key from daemon, but in integrations/swarm
        // testing we are not able to do that, so we extract the key as a
        // command line option:
        legacy_seckey private_key{};
        ed25519_seckey private_key_ed25519{};
        x25519_seckey private_key_x25519{};
        try {
            private_key = legacy_seckey::from_hex(options.oxend_key);
            private_key_ed25519 = ed25519_seckey::from_hex(options.oxend_ed25519_key);
            private_key_x25519 = x25519_seckey::from_hex(options.oxend_x25519_key);
        } catch (...) {
            OXEN_LOG(critical, "This storage server binary is compiled in integration test mode: "
                "--oxend-key, --oxend-x25519-key, and --oxend-ed25519-key are required");
            throw;
        }
#endif

        sn_record_t me{"0.0.0.0", options.port, options.lmq_port,
                private_key.pubkey(), private_key_ed25519.pubkey(), private_key_x25519.pubkey()};

        OXEN_LOG(info, "Retrieved keys from oxend; our SN pubkeys are:");
        OXEN_LOG(info, "- legacy:  {}", me.pubkey_legacy);
        OXEN_LOG(info, "- ed25519: {}", me.pubkey_ed25519);
        OXEN_LOG(info, "- x25519:  {}", me.pubkey_x25519);
        OXEN_LOG(info, "- lokinet: {}", me.pubkey_ed25519.snode_address());

        ChannelEncryption channel_encryption{private_key_x25519, me.pubkey_x25519};

        // Set up oxenmq now, but don't actually start it until after we set up the ServiceNode
        // instance (because ServiceNode and OxenmqServer reference each other).
        OxenmqServer oxenmq_server{me, private_key_x25519, stats_access_keys};

        // TODO: SN doesn't need oxenmq_server, just the lmq components
        ServiceNode service_node(ioc, me, private_key, oxenmq_server,
                                       options.data_dir, options.force_start);

        RequestHandler request_handler(ioc, service_node, channel_encryption);

        oxenmq_server.init(&service_node, &request_handler,
                oxenmq::address{options.oxend_omq_rpc});

        RateLimiter rate_limiter;

        Security security(legacy_keypair{me.pubkey_legacy, private_key}, options.data_dir);

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        oxenmq_server->add_timer([&service_node] {
            sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
        }, 10s);
#endif

        http_server::run(ioc, options.ip, options.port, options.data_dir,
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
