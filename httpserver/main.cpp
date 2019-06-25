#include "../common/src/common.h"
#include "channel_encryption.hpp"
#include "http_connection.h"
#include "lokid_key.h"
#include "rate_limiter.h"
#include "service_node.h"
#include "swarm.h"
#include "version.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include <boost/core/null_deleter.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
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
namespace fs = boost::filesystem;
namespace po = boost::program_options;
namespace logging = boost::log;

using LogLevelPair = std::pair<std::string, spdlog::level::level_enum>;
using LogLevelMap = std::vector<LogLevelPair>;
static const LogLevelMap logLevelMap{
    {"trace", spdlog::level::trace},
    {"debug", spdlog::level::debug},
    {"info", spdlog::level::info},
    {"warning", spdlog::level::warn},
    {"error", spdlog::level::err},
};

static void print_usage(const po::options_description& desc, char* argv[]) {

    std::cerr << std::endl;
    std::cerr << "Usage: " << argv[0] << " <address> <port> [...]\n\n";

    desc.print(std::cerr);

    std::cerr << std::endl;
    std::cerr << "  Log Levels:\n";
    for (const auto& logLevel : logLevelMap) {
        std::cerr << "    " << logLevel.first << "\n";
    }
}

static bool parse_log_level(const std::string& input, spdlog::level::level_enum & logLevel) {

    const auto it = std::find_if(
        logLevelMap.begin(), logLevelMap.end(),
        [&](const LogLevelPair& pair) { return pair.first == input; });
    if (it != logLevelMap.end()) {
        logLevel = it->second;
        return true;
    }
    return false;
}

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

static void init_logging(const fs::path& data_dir, spdlog::level::level_enum log_level) {

    const std::string log_location = (data_dir / "storage.logs").string();
    // Log to disk output stream
    auto input = boost::shared_ptr<std::ofstream>(
        new std::ofstream(log_location, std::ios::out | std::ios::app));
    if (input->is_open()) {
        input->close();
    } else {
        std::cerr << "Could not open " << log_location << std::endl;
        return;
    }

    constexpr size_t LOG_FILE_SIZE_LIMIT = 1024 * 1024 * 50; // 50Mb
    constexpr size_t EXTRA_FILES = 1;

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(log_level);

    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_location, LOG_FILE_SIZE_LIMIT, EXTRA_FILES);
    file_sink->set_level(log_level);

    std::vector<spdlog::sink_ptr> sinks = {console_sink, file_sink};

    auto logger = std::make_shared<spdlog::logger>("loki_logger", sinks.begin(),
                                                   sinks.end());
    spdlog::register_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

    LOKI_LOG(info,
             "\n**************************************************************"
             "\nOutputting logs to {}",
             log_location);
}

int main(int argc, char* argv[]) {

    try {
        // Check command line arguments.
        std::string lokid_key_path;

        const auto home_dir = get_home_dir();
        const fs::path data_dir =
            home_dir ? (*home_dir / ".loki" / "storage") : ".";

        std::string data_dir_str = data_dir.string();
        std::string log_level_string("info");
        bool print_version = false;
        uint16_t lokid_rpc_port = 22023;

        po::options_description desc;
        // clang-format off
        desc.add_options()
            ("lokid-key", po::value(&lokid_key_path), "Path to the Service Node key file")
            ("data-dir", po::value(&data_dir_str),"Path to persistent data")
            ("log-level", po::value(&log_level_string), "Log verbosity level, see Log Levels below for accepted values")
            ("version,v", po::bool_switch(&print_version), "Print the version of this binary")
            ("lokid-rpc-port", po::value(&lokid_rpc_port), "RPC port on which the local Loki daemon is listening");
        // clang-format on

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (argc < 2) {
            print_usage(desc, argv);
            return EXIT_FAILURE;
        }

        std::cout << "Loki Storage Server v" << STORAGE_SERVER_VERSION_STRING
                  << std::endl
                  << " git commit hash: " << STORAGE_SERVER_GIT_HASH_STRING
                  << std::endl
                  << " build time: " << STORAGE_SERVER_BUILD_TIME << std::endl;

        if (print_version) {
            return EXIT_SUCCESS;
        }

        if (argc < 3) {
            print_usage(desc, argv);
            return EXIT_FAILURE;
        }

        const auto port = static_cast<uint16_t>(std::atoi(argv[2]));
        std::string ip = argv[1];

        if (!fs::exists(data_dir_str)) {
            fs::create_directories(data_dir_str);
        }

        spdlog::level::level_enum log_level;
        if (!parse_log_level(log_level_string, log_level)) {
            LOKI_LOG(error, "Incorrect log level {}", log_level_string);
            print_usage(desc, argv);
            return EXIT_FAILURE;
        }

        init_logging(data_dir_str, log_level);

        LOKI_LOG(info, "Setting log level to {}", log_level_string);

        LOKI_LOG(info, "Setting database location to {}", data_dir_str);

        if (vm.count("lokid-key")) {
            LOKI_LOG(info, "Setting Lokid key path to {}", lokid_key_path);
        }

        if (vm.count("lokid-rpc-port")) {
            LOKI_LOG(info, "Setting lokid RPC port to {}", lokid_rpc_port);
        }

        LOKI_LOG(info, "Listening at address {} port {}", ip, port);

        boost::asio::io_context ioc{1};
        boost::asio::io_context worker_ioc{1};

        if (sodium_init() != 0) {
            LOKI_LOG(error, "Could not initialize libsodium");
            return EXIT_FAILURE;
        }

        // ed25519 key
        const auto private_key = loki::parseLokidKey(lokid_key_path);
        const auto public_key = loki::calcPublicKey(private_key);

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key.begin(), private_key.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        loki::lokid_key_pair_t lokid_key_pair{private_key, public_key};

        auto lokid_client = loki::LokidClient(ioc, lokid_rpc_port);

        loki::ServiceNode service_node(ioc, worker_ioc, port, lokid_key_pair,
                                       data_dir_str, lokid_client);
        RateLimiter rate_limiter;

        /// Should run http server
        loki::http_server::run(ioc, ip, port, data_dir_str, service_node,
                               channel_encryption, rate_limiter);

    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        LOKI_LOG(error, "Exception caught in main: {}", e.what());
        return EXIT_FAILURE;
    } catch (...) {
        LOKI_LOG(error, "Unknown exception caught in main.");
        return EXIT_FAILURE;
    }
}
