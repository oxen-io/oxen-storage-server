#include "channel_encryption.hpp"
#include "command_line.h"
#include "https_server.h"
#include "oxen_logger.h"
#include "oxend_key.h"
#include "oxend_rpc.h"
#include "server_certificates.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "omq_server.h"
#include "request_handler.h"

#include <sodium/core.h>
#include <oxenmq/oxenmq.h>
#include <oxenmq/hex.h>

#include <csignal>
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

std::atomic<int> signalled = 0;
extern "C" void handle_signal(int sig) {
    signalled = sig;
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

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

    std::filesystem::path data_dir;
    if (options.data_dir.empty()) {
        if (auto home_dir = util::get_home_dir()) {
            data_dir = options.testnet
                ? *home_dir / ".oxen" / "testnet" / "storage"
                : *home_dir / ".oxen" / "storage";
        } else {
            std::cerr << "Could not determine your home directory; please use --data-dir to specify a data directory\n";
            return EXIT_FAILURE;
        }
    } else {
        data_dir = std::filesystem::u8path(options.data_dir);
    }

    if (!fs::exists(data_dir))
        fs::create_directories(data_dir);

    oxen::LogLevel log_level;
    if (!oxen::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        oxen::print_log_levels();
        return EXIT_FAILURE;
    }

    oxen::init_logging(data_dir, log_level);

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
    OXEN_LOG(info, "Setting database location to {}", data_dir);
    OXEN_LOG(info, "Connecting to oxend @ {}", options.oxend_omq_rpc);

    if (sodium_init() != 0) {
        OXEN_LOG(err, "Could not initialize libsodium");
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
            get_sn_privkeys(options.oxend_omq_rpc, [] { return signalled == 0; });
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
        if (signalled) {
            OXEN_LOG(err, "Received signal {}, aborting startup", signalled.load());
            return EXIT_FAILURE;
        }

        sn_record me{"0.0.0.0", options.port, options.omq_port,
                private_key.pubkey(), private_key_ed25519.pubkey(), private_key_x25519.pubkey()};

        OXEN_LOG(info, "Retrieved keys from oxend; our SN pubkeys are:");
        OXEN_LOG(info, "- legacy:  {}", me.pubkey_legacy);
        OXEN_LOG(info, "- ed25519: {}", me.pubkey_ed25519);
        OXEN_LOG(info, "- x25519:  {}", me.pubkey_x25519);
        OXEN_LOG(info, "- lokinet: {}", me.pubkey_ed25519.snode_address());

        ChannelEncryption channel_encryption{private_key_x25519, me.pubkey_x25519};

        auto ssl_cert = data_dir / "cert.pem";
        auto ssl_key = data_dir / "key.pem";
        auto ssl_dh = data_dir / "dh.pem";
        if (!exists(ssl_cert) || !exists(ssl_key))
            generate_cert(ssl_cert, ssl_key);
        if (!exists(ssl_dh))
            generate_dh_pem(ssl_dh);

        // Set up oxenmq now, but don't actually start it until after we set up the ServiceNode
        // instance (because ServiceNode and OxenmqServer reference each other).
        auto oxenmq_server_ptr = std::make_unique<OxenmqServer>(me, private_key_x25519, stats_access_keys);
        auto& oxenmq_server = *oxenmq_server_ptr;

        ServiceNode service_node{
            me, private_key, oxenmq_server, data_dir, options.force_start};

        RequestHandler request_handler{service_node, channel_encryption, private_key_ed25519};

        RateLimiter rate_limiter{*oxenmq_server};

        HTTPSServer https_server{service_node, request_handler, rate_limiter,
            {{options.ip, options.port, true}},
            ssl_cert, ssl_key, ssl_dh,
            {me.pubkey_legacy, private_key}};


        oxenmq_server.init(&service_node, &request_handler, &rate_limiter,
                oxenmq::address{options.oxend_omq_rpc});

        https_server.start();

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        oxenmq_server->add_timer([&service_node] {
            sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
        }, 10s);
#endif

        // Log general stats at startup and again every hour
        OXEN_LOG(info, service_node.get_status_line());
        oxenmq_server->add_timer(
                [&service_node] { OXEN_LOG(info, service_node.get_status_line()); }, 1h);

        while (signalled.load() == 0)
            std::this_thread::sleep_for(100ms);

        OXEN_LOG(warn, "Received signal {}; shutting down...", signalled.load());
        service_node.shutdown();
        OXEN_LOG(info, "Stopping https server");
        https_server.shutdown(true);
        OXEN_LOG(info, "Stopping omq server");
        oxenmq_server_ptr.reset();
        OXEN_LOG(info, "Shutting down");
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
