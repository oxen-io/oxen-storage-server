#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "loki_logger.h"
#include "lokid_key.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "version.h"

#include <boost/filesystem.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <vector>

namespace fs = boost::filesystem;

static boost::optional<fs::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifdef WIN32
    return boost::none;
#endif

    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        return boost::none;

    return fs::path(pszHome);
}

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

    if (options.data_dir.empty()) {
        if (auto home_dir = get_home_dir()) {
            options.data_dir = (home_dir.get() / ".loki" / "storage").string();
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

    // Always print version for the logs
    print_version();
    if (options.print_version) {
        return EXIT_SUCCESS;
    }

    if (options.ip == "127.0.0.1") {
        LOKI_LOG(error, "Tried to bind loki-storage to localhost, please bind to outward facing address");
        return EXIT_FAILURE;
    }

    if (options.port == options.lokid_rpc_port) {
        LOKI_LOG(error, "Storage server port must be different from that of Lokid! Terminating.");
        exit(EXIT_INVALID_PORT);
    }

    LOKI_LOG(info, "Setting log level to {}", options.log_level);
    LOKI_LOG(info, "Setting database location to {}", options.data_dir);
    LOKI_LOG(info, "Setting Lokid key path to {}", options.lokid_key_path);
    LOKI_LOG(info, "Setting Lokid RPC port to {}", options.lokid_rpc_port);
    LOKI_LOG(info, "Listening at address {} port {}", options.ip, options.port);

#ifdef DISABLE_SNODE_SIGNATURE
    LOKI_LOG(warn, "IMPORTANT: This binary is compiled with Service Node "
                   "signatures disabled, make sure this is intentional!");
#endif

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        LOKI_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    try {

        // ed25519 key
        const auto private_key = loki::parseLokidKey(options.lokid_key_path);
        const auto public_key = loki::calcPublicKey(private_key);

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key.begin(), private_key.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        loki::lokid_key_pair_t lokid_key_pair{private_key, public_key};

        auto lokid_client = loki::LokidClient(ioc, options.lokid_rpc_port);

        loki::ServiceNode service_node(ioc, worker_ioc, options.port,
                                       lokid_key_pair, options.data_dir,
                                       lokid_client, options.force_start);
        RateLimiter rate_limiter;

        loki::Security security(lokid_key_pair, options.data_dir);

        /// Should run http server
        loki::http_server::run(ioc, options.ip, options.port, options.data_dir,
                               service_node, channel_encryption, rate_limiter,
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
