#include "Storage.hpp"
#include "http_connection.hpp"
#include "channel_encryption.hpp"

#include <boost/program_options.hpp>

#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>

using namespace service_node;
namespace po = boost::program_options;

void usage(char* argv[]) {
    std::cerr << "Usage: " << argv[0] << " <address> <port> [--lokinet-identity path] [--db-location path]\n";
    std::cerr << "  For IPv4, try:\n";
    std::cerr << "    receiver 0.0.0.0 80\n";
    std::cerr << "  For IPv6, try:\n";
    std::cerr << "    receiver 0::0 80\n";
}

int main(int argc, char* argv[]) {
    try {
        // Check command line arguments.
        if (argc < 3) {
            usage(argv);
            return EXIT_FAILURE;
        }
        
        std::string lokinetIdentityPath;
        std::string dbLocation(".");
        auto const address = boost::asio::ip::make_address(argv[1]);
        unsigned short port = static_cast<unsigned short>(std::atoi(argv[2]));
        
        po::options_description desc;
        desc.add_options()
        ("lokinet-identity", po::value(&lokinetIdentityPath), "")
        ("db-location", po::value(&dbLocation), "")
        ;
        
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        
        if (vm.count("lokinet-identity")) {
            std::cout << "Setting identity.private path to " << lokinetIdentityPath << std::endl;
        }
        
        if (vm.count("db-location")) {
            std::cout << "Setting database location to " << dbLocation << std::endl;;
        }
        
        
        std::cout << "Listening at address " << argv[1] << " port " << argv[2]
                  << std::endl;

        boost::asio::io_context ioc{1};

        Storage storage(dbLocation);
        ChannelEncryption<std::string> channelEncryption(lokinetIdentityPath);

        tcp::acceptor acceptor{ioc, {address, port}};
        tcp::socket socket{ioc};
        http_server(acceptor, socket, storage, channelEncryption);

        ioc.run();
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
