#include "command_line.h"
#include <oxenss/common/mainnet.h>
#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/oxend_rpc.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/https.h>
#include <oxenss/server/omq.h>
#include <oxenss/server/server_certificates.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/version.h>

#include <oxenmq/oxenmq.h>
#include <sodium/core.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <variant>
#include <vector>

extern "C" {
#include <sys/types.h>
#include <unistd.h>

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

    using namespace oxen;

    auto parsed = cli::parse_cli_args(argc, argv);
    if (auto* code = std::get_if<int>(&parsed))
        return *code;

    auto& options = var::get<cli::command_line_options>(parsed);

    if (!fs::exists(options.data_dir))
        fs::create_directories(options.data_dir);

    logging::LogLevel log_level;
    if (auto level = logging::parse_level(options.log_level)) {
        log_level = *level;
    } else {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        logging::print_levels();
        return EXIT_FAILURE;
    }

    logging::init(options.data_dir, log_level);

    if (options.testnet) {
        is_mainnet = false;
        OXEN_LOG(warn, "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    OXEN_LOG(info, "{}", STORAGE_SERVER_VERSION_INFO);

    if (options.ip == "127.0.0.1") {
        OXEN_LOG(
                critical,
                "Tried to bind oxen-storage to localhost, please bind "
                "to outward facing address");
        return EXIT_FAILURE;
    }

    OXEN_LOG(info, "Setting log level to {}", options.log_level);
    OXEN_LOG(info, "Setting database location to {}", options.data_dir);
    OXEN_LOG(info, "Connecting to oxend @ {}", options.oxend_omq_rpc);

    if (sodium_init() != 0) {
        OXEN_LOG(err, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (const auto fd_limit = sysconf(_SC_OPEN_MAX); fd_limit != -1) {
        OXEN_LOG(debug, "Open file descriptor limit: {}", fd_limit);
    } else {
        OXEN_LOG(debug, "Open descriptor limit: N/A");
    }

    try {
        std::vector<crypto::x25519_pubkey> stats_access_keys;
        for (const auto& key : options.stats_access_keys) {
            stats_access_keys.push_back(crypto::x25519_pubkey::from_hex(key));
            OXEN_LOG(info, "Stats access key: {}", key);
        }

        const auto [private_key, private_key_ed25519, private_key_x25519] =
                rpc::get_sn_privkeys(options.oxend_omq_rpc, [] { return signalled == 0; });

        if (signalled) {
            OXEN_LOG(err, "Received signal {}, aborting startup", signalled.load());
            return EXIT_FAILURE;
        }

        snode::sn_record me{
                "0.0.0.0",
                options.https_port,
                options.omq_port,
                private_key.pubkey(),
                private_key_ed25519.pubkey(),
                private_key_x25519.pubkey()};

        OXEN_LOG(info, "Retrieved keys from oxend; our SN pubkeys are:");
        OXEN_LOG(info, "- legacy:  {}", me.pubkey_legacy);
        OXEN_LOG(info, "- ed25519: {}", me.pubkey_ed25519);
        OXEN_LOG(info, "- x25519:  {}", me.pubkey_x25519);
        OXEN_LOG(info, "- lokinet: {}", me.pubkey_ed25519.snode_address());

        crypto::ChannelEncryption channel_encryption{private_key_x25519, me.pubkey_x25519};

        auto ssl_cert = options.data_dir / "cert.pem";
        auto ssl_key = options.data_dir / "key.pem";
        auto ssl_dh = options.data_dir / "dh.pem";
        if (!exists(ssl_cert) || !exists(ssl_key))
            generate_cert(ssl_cert, ssl_key);
        if (!exists(ssl_dh))
            generate_dh_pem(ssl_dh);

        // Set up oxenmq now, but don't actually start it until after we set up the ServiceNode
        // instance (because ServiceNode and OxenmqServer reference each other).
        auto oxenmq_server_ptr =
                std::make_unique<server::OMQ>(me, private_key_x25519, stats_access_keys);
        auto& oxenmq_server = *oxenmq_server_ptr;

        snode::ServiceNode service_node{
                me, private_key, oxenmq_server, options.data_dir, options.force_start};

        rpc::RequestHandler request_handler{service_node, channel_encryption, private_key_ed25519};

        rpc::RateLimiter rate_limiter{*oxenmq_server};

        server::HTTPS https_server{
                service_node,
                request_handler,
                rate_limiter,
                {{options.ip, options.https_port, true}},
                ssl_cert,
                ssl_key,
                ssl_dh,
                {me.pubkey_legacy, private_key}};

        oxenmq_server.init(
                &service_node,
                &request_handler,
                &rate_limiter,
                oxenmq::address{options.oxend_omq_rpc});

        https_server.start();

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        oxenmq_server->add_timer(
                [&service_node] {
                    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
                },
                10s);
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
