#include "Storage.hpp"
#include "channel_encryption.hpp"
#include "http_connection.hpp"

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include <cstdlib>
#include <iomanip>
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
              << " <address> <port> [--lokinet-identity path] [--db-location "
                 "path] [--log-level level]\n";
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

std::vector<std::function<void(void)> > closers;

void handle_signal(int)
{
  for(auto & f : closers)
    f();
  closers.clear();
}

int main(int argc, char* argv[]) {
    try {
        // Check command line arguments.
        if (argc < 3) {
            usage(argv);
            return EXIT_FAILURE;
        }
        boost::asio::io_context ioc{1};

        std::string lokinetIdentityPath;
        std::string dbLocation(".");
        std::string logLevelString("info");
        
        po::options_description desc;
        desc.add_options()("lokinet-identity", po::value(&lokinetIdentityPath),
                           "")("db-location", po::value(&dbLocation),
                               "")("log-level", po::value(&logLevelString), "");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        logging::trivial::severity_level logLevel;
        if (!parseLogLevel(logLevelString, logLevel)) {
            BOOST_LOG_TRIVIAL(error) << "Incorrect log level" << logLevelString;
            usage(argv);
            return EXIT_FAILURE;
        }

        logging::core::get()->set_filter(logging::trivial::severity >=
                                         logLevel);
        BOOST_LOG_TRIVIAL(info) << "Setting log level to " << logLevelString;

        if (vm.count("lokinet-identity")) {
            BOOST_LOG_TRIVIAL(info)
                << "Setting identity.private path to " << lokinetIdentityPath;
        }

        if (vm.count("db-location")) {
            BOOST_LOG_TRIVIAL(info)
                << "Setting database location to " << dbLocation;
        }
        using endpoint_t = boost::asio::ip::tcp::endpoint;
        endpoint_t ep;
        {
          using err_t = boost::system::error_code;
          using resolver_t = boost::asio::ip::tcp::resolver;
          resolver_t r{ioc};
          err_t ec;
          auto res = r.resolve(resolver_t::query(argv[1], argv[2]), ec);
          if(ec)
          {
            BOOST_LOG_TRIVIAL(fatal) << "failed to resolve " << argv[1] << ":" << argv[2] << ", " << ec.message() ;
            return EXIT_FAILURE;
          }
          ep = *res;
        }
        BOOST_LOG_TRIVIAL(info) << "Listening at address " << argv[1]
                                << " port " << argv[2] ;

        Storage storage(dbLocation);
        ChannelEncryption<std::string> channelEncryption(lokinetIdentityPath);

        tcp::acceptor acceptor{ioc, ep};
        tcp::socket socket{ioc};
        http_server(acceptor, socket, storage, channelEncryption);

        closers.emplace_back([&]() {
            BOOST_LOG_TRIVIAL(info) << "closing..." ;
            acceptor.close();
            ioc.stop();
            BOOST_LOG_TRIVIAL(info) << "bye" ;
        });
        
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);

        ioc.run();
        return 0;
    } catch (std::exception const& e) {
        BOOST_LOG_TRIVIAL(fatal) << "Error: " << e.what();
        return EXIT_FAILURE;
    }
}
