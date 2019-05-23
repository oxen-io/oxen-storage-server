#include "channel_encryption.hpp"
#include "http_connection.h"
#include "lokid_key.h"
#include "rate_limiter.h"
#include "service_node.h"
#include "swarm.h"
#include "version.h"

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/program_options.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <utility> // for std::pair
#include <vector>

using namespace service_node;
namespace po = boost::program_options;
namespace logging = boost::log;

using LogLevelPair = std::pair<std::string, logging::trivial::severity_level>;
using LogLevelMap = std::vector<LogLevelPair>;
static const LogLevelMap logLevelMap{
    {"trace", logging::trivial::severity_level::trace},
    {"debug", logging::trivial::severity_level::debug},
    {"info", logging::trivial::severity_level::info},
    {"warning", logging::trivial::severity_level::warning},
    {"error", logging::trivial::severity_level::error},
    {"fatal", logging::trivial::severity_level::fatal},
};

void usage(char* argv[]) {
    std::cerr << "Usage: " << argv[0]
              << " <address> <port> --lokid-key path [--db-location "
                 "path] [--log-level level] [--output-log path] [--version]\n";
    std::cerr << "  For IPv4, try:\n";
    std::cerr << "    receiver 0.0.0.0 80\n";
    std::cerr << "  For IPv6, try:\n";
    std::cerr << "    receiver 0::0 80\n";
    std::cerr << "  Log levels:\n";
    for (const auto& logLevel : logLevelMap) {
        std::cerr << "    " << logLevel.first << "\n";
    }
}

bool parseLogLevel(const std::string& input,
                   logging::trivial::severity_level& logLevel) {

    const auto it = std::find_if(
        logLevelMap.begin(), logLevelMap.end(),
        [&](const LogLevelPair& pair) { return pair.first == input; });
    if (it != logLevelMap.end()) {
        logLevel = it->second;
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    try {
        // Check command line arguments.
        if (argc < 2) {
            usage(argv);
            return EXIT_FAILURE;
        }

        std::string lokid_key_path;
        std::string db_location(".");
        std::string log_location;
        std::string log_level_string("info");
        bool print_version = false;
        uint16_t lokid_rpc_port = 22023;

        po::options_description desc;
        desc.add_options()("lokid-key", po::value(&lokid_key_path),
                           "")("db-location", po::value(&db_location),
                               "")("output-log", po::value(&log_location), "")(
            "log-level", po::value(&log_level_string),
            "")("version,v", po::bool_switch(&print_version),
                "")("lokid-rpc-port", po::value(&lokid_rpc_port));

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        std::cout << "Loki Storage Server v" << STORAGE_SERVER_VERSION_STRING
                  << std::endl
                  << " git commit hash: " << STORAGE_SERVER_GIT_HASH_STRING
                  << std::endl
                  << " build time: " << STORAGE_SERVER_BUILD_TIME << std::endl;

        if (print_version) {
            return EXIT_SUCCESS;
        }

        if (argc < 3) {
            usage(argv);
            return EXIT_FAILURE;
        }

        const auto port = static_cast<uint16_t>(std::atoi(argv[2]));
        std::string ip = argv[1];

        if (vm.count("output-log")) {

            // TODO: remove this line once confirmed that no one
            // is relying on this
            log_location += ".out";

            // Hacky, but I couldn't find a way to recover from
            // boost throwing on invalid file and apparently poisoning
            // the logging mechanism...
            std::ofstream input(log_location);

            if (input.is_open()) {
                input.close();
                auto sink = logging::add_file_log(log_location);
                sink->locked_backend()->auto_flush(true);
                BOOST_LOG_TRIVIAL(info)
                    << "Outputting logs to " << log_location;
            } else {
                BOOST_LOG_TRIVIAL(error) << "Could not open " << log_location;
            }
        }

        logging::trivial::severity_level logLevel;
        if (!parseLogLevel(log_level_string, logLevel)) {
            BOOST_LOG_TRIVIAL(error)
                << "Incorrect log level" << log_level_string;
            usage(argv);
            return EXIT_FAILURE;
        }

        // TODO: consider adding auto-flushing for logging
        logging::core::get()->set_filter(logging::trivial::severity >=
                                         logLevel);
        BOOST_LOG_TRIVIAL(info) << "Setting log level to " << log_level_string;

        if (vm.count("lokid-key")) {
            BOOST_LOG_TRIVIAL(info)
                << "Setting Lokid key path to " << lokid_key_path;
        }

        if (vm.count("db-location")) {
            BOOST_LOG_TRIVIAL(info)
                << "Setting database location to " << db_location;
        }

        if (vm.count("lokid-rpc-port")) {
            BOOST_LOG_TRIVIAL(info)
                << "Setting lokid RPC port to " << lokid_rpc_port;
        }

        BOOST_LOG_TRIVIAL(info)
            << "Listening at address " << ip << " port " << port << std::endl;

        boost::asio::io_context ioc{1};

        if (sodium_init() != 0) {
            BOOST_LOG_TRIVIAL(fatal) << "Could not initialize libsodium";
            return EXIT_FAILURE;
        }

        // ed25519 key
        const auto private_key = loki::parseLokidKey(lokid_key_path);
        const auto public_key = loki::calcPublicKey(private_key);

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key.begin(), private_key.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        loki::lokid_key_pair_t lokid_key_pair{private_key, public_key};
        loki::ServiceNode service_node(ioc, port, lokid_key_pair, db_location,
                                       lokid_rpc_port);
        RateLimiter rate_limiter;

        /// Should run http server
        loki::http_server::run(ioc, ip, port, service_node, channel_encryption,
                               rate_limiter);

    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        BOOST_LOG_TRIVIAL(fatal) << "Exception caught in main: " << e.what();
        return EXIT_FAILURE;
    } catch (...) {
        BOOST_LOG_TRIVIAL(fatal) << "Unknown exception caught in main.";
        return EXIT_FAILURE;
    }
}
