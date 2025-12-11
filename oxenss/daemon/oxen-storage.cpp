#include "command_line.h"
#include <oxenss/common/mainnet.h>
#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/oxend_rpc.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/https.h>
#include <oxenss/server/omq.h>
#include <oxenss/server/quic.h>
#include <oxenss/server/server_certificates.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/version.h>

#include <oxenmq/oxenmq.h>
#include <sodium/core.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
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

static auto logcat = oxen::log::Cat("daemon");

std::atomic<int> signalled = 0;
extern "C" void handle_signal(int sig) {
    signalled = sig;
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    using namespace oxenss;

    auto parsed = cli::parse_cli_args(argc, argv);
    if (auto* code = std::get_if<int>(&parsed))
        return *code;

    auto& options = std::get<cli::command_line_options>(parsed);

    if (!fs::exists(options.data_dir))
        fs::create_directories(options.data_dir);

    log::Level log_level;
    try {
        log_level = log::level_from_string(options.log_level);
    } catch (const std::invalid_argument& e) {
        log::critical(
                logcat,
                "{}; supported levels: trace, debug, info, warn, error, critical, off",
                e.what(),
                options.log_level);
        return EXIT_FAILURE;
    }

    logging::init(options.data_dir, log_level);

    if (options.testnet) {
        is_mainnet = false;
        log::warning(logcat, "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    log::info(logcat, "{}", STORAGE_SERVER_VERSION_INFO);

    log::info(logcat, "Setting log level to {}", options.log_level);
    log::info(logcat, "Setting database location to {}", util::to_sv(options.data_dir.u8string()));
    log::info(logcat, "Connecting to oxend @ {}", options.oxend_omq_rpc);

    // Validate the OMQ RPC address can be converted, especially since bad address conversions can
    // throw an exception that might _not_ be caught and propagate up to main, providing zero
    // context on the whereabouts of the error.
    try {
        oxenmq::address{options.oxend_omq_rpc};
    } catch (const std::exception& e) {
        log::error(
                logcat,
                "OMQ RPC address '{}' was not a valid for ZMQ communications (e.g. "
                "tcp://HOSTNAME:PORT or ipc://PATH, lookup OxenMQ addresses for more information)",
                options.oxend_omq_rpc);
        return EXIT_FAILURE;
    }

    if (sodium_init() != 0) {
        log::error(logcat, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (const auto fd_limit = sysconf(_SC_OPEN_MAX); fd_limit != -1) {
        log::debug(logcat, "Open file descriptor limit: {}", fd_limit);
    } else {
        log::debug(logcat, "Open descriptor limit: N/A");
    }

    try {
        std::vector<crypto::x25519_pubkey> stats_access_keys;
        for (const auto& key : options.stats_access_keys) {
            stats_access_keys.push_back(crypto::x25519_pubkey::from_hex(key));
            log::info(logcat, "Stats access key: {}", key);
        }

        const auto [l_keys, ed_keys, x_keys] =
                rpc::get_sn_keys(options.oxend_omq_rpc, [] { return signalled == 0; });

        if (signalled) {
            log::error(logcat, "Received signal {}, aborting startup", signalled.load());
            return EXIT_FAILURE;
        }

        snode::contact me{
                oxen::quic::ipv4{0},
                options.https_port,
                options.omq_quic_port,
                STORAGE_SERVER_VERSION,
                ed_keys.pub,
                x_keys.pub};

        log::info(logcat, "Retrieved keys from oxend; our SN pubkeys are:");
        log::info(logcat, "- legacy:  {}", l_keys.pub);
        log::info(logcat, "- ed25519: {}", me.pubkey_ed25519);
        log::info(logcat, "- x25519:  {}", me.pubkey_x25519);
        log::info(logcat, "- lokinet: {}", me.pubkey_ed25519.snode_address());

        crypto::ChannelEncryption channel_encryption{x_keys};

        auto ssl_cert = options.data_dir / "cert.pem";
        auto ssl_key = options.data_dir / "key.pem";
        auto ssl_dh = options.data_dir / "dh.pem";
        if (!exists(ssl_cert) || !exists(ssl_key))
            generate_cert(ssl_cert, ssl_key);
        if (!exists(ssl_dh))
            generate_dh_pem(ssl_dh);

        // Set up oxenmq now, but don't actually start it until after we set up the ServiceNode
        // instance (because ServiceNode and OxenmqServer reference each other).
        auto oxenmq_server_ptr = std::make_unique<server::OMQ>(x_keys, stats_access_keys);
        auto& oxenmq_server = *oxenmq_server_ptr;

        snode::ServiceNode service_node{
                l_keys, me, oxenmq_server, options.data_dir, options.force_start};

        rpc::RequestHandler request_handler{service_node, channel_encryption, ed_keys.sec};

        rpc::RateLimiter rate_limiter{*oxenmq_server};

        std::vector<std::tuple<std::string, uint16_t, bool>> https_bind;
        std::vector<oxen::quic::Address> quic_bind;
#ifdef IPV6_V6ONLY
        // If this define is set then listen in dual stack mode.  uWebSockets doesn't give us any
        // way to disable this; for quic it's a flag on the address object.
        https_bind.emplace_back("::", options.https_port, true);
        quic_bind.emplace_back("::", options.omq_quic_port);
        quic_bind.back().dual_stack = true;
#else
        https_bind.emplace_back("0.0.0.0", options.https_port, true);
        https_bind.emplace_back("::", options.https_port, true);

        quic_bind.emplace_back("0.0.0.0", options.omq_quic_port);
        quic_bind.emplace_back("::", options.omq_quic_port);
        quic_bind.back().dual_stack = false;
#endif

        server::HTTPS https_server{
                service_node,
                request_handler,
                rate_limiter,
                std::move(https_bind),
                ssl_cert,
                ssl_key,
                ssl_dh,
                l_keys};

        auto quic = std::make_unique<server::QUIC>(
                service_node, request_handler, rate_limiter, std::move(quic_bind), ed_keys.sec);
        service_node.register_mq_server(quic.get());

        auto http_client = std::make_shared<http::Client>(quic->loop);
        service_node.set_http_client(http_client);
        request_handler.set_http_client(http_client);

        oxenmq_server.init(
                &service_node,
                &request_handler,
                &rate_limiter,
                oxenmq::address{options.oxend_omq_rpc});

        quic->startup_endpoint();

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
        log::info(logcat, "{}", service_node.get_status_line());
        oxenmq_server->add_timer(
                [&service_node] { log::info(logcat, "{}", service_node.get_status_line()); }, 1h);

        while (signalled.load() == 0)
            std::this_thread::sleep_for(100ms);

        log::warning(logcat, "Received signal {}; shutting down...", signalled.load());
        http_client.reset();  // Kills outgoing requests and prevents new ones.  Also depends on
                              // `quic`'s event loop so *must* be destroyed before `quic`.
        service_node.shutdown();
        log::info(logcat, "Stopping https server");
        https_server.shutdown(true);
        log::info(logcat, "Stopping quic server");
        quic.reset();
        log::info(logcat, "Stopping omq server");
        oxenmq_server_ptr.reset();
        log::info(logcat, "Shutting down");
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
