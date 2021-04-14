#include "command_line.h"
#include "oxen_logger.h"
#include "utils.hpp"

#include <filesystem>
#include <iostream>

namespace oxen {

namespace po = boost::program_options;
namespace fs = std::filesystem;

const command_line_options& command_line_parser::get_options() const {
    return options_;
}

void command_line_parser::parse_args(int argc, char* argv[]) {
    std::string config_file;
    po::options_description all, hidden;
    auto home = util::get_home_dir().value_or(".");
    options_.oxend_omq_rpc = "ipc://" + (home / ".oxen" / "oxend.sock").u8string();
    std::string old_rpc_ip;
    uint16_t old_rpc_port = 0;
    // clang-format off
    desc_.add_options()
        ("data-dir", po::value(&options_.data_dir), "Path to persistent data (defaults to ~/.oxen/storage)")
        ("config-file", po::value(&config_file), "Path to custom config file (defaults to `storage-server.conf' inside --data-dir)")
        ("log-level", po::value(&options_.log_level), "Log verbosity level, see Log Levels below for accepted values")
        ("oxend-rpc", po::value(&options_.oxend_omq_rpc), "OMQ RPC address on which oxend is available; typically ipc:///path/to/oxend.sock or tcp://localhost:22025")
        ("lmq-port", po::value(&options_.lmq_port), "Public port to listen on for OxenMQ connections")
        ("testnet", po::bool_switch(&options_.testnet), "Start storage server in testnet mode")
        ("force-start", po::bool_switch(&options_.force_start), "Ignore the initialisation ready check")
        ("bind-ip", po::value(&options_.ip)->default_value("0.0.0.0"), "IP to which to bind the server")
        ("version,v", po::bool_switch(&options_.print_version), "Print the version of this binary")
        ("help", po::bool_switch(&options_.print_help),"Shows this help message")
        ("stats-access-key", po::value(&options_.stats_access_keys)->multitoken(), "A public key (x25519) that will be given access to the `get_stats` lmq endpoint")
#ifdef INTEGRATION_TEST
        ("oxend-key", po::value(&options_.oxend_key), "Legacy secret key (integration testing only)")
        ("oxend-x25519-key", po::value(&options_.oxend_x25519_key), "x25519 secret key (integration testing only)")
        ("oxend-ed25519-key", po::value(&options_.oxend_ed25519_key), "ed25519 public key (integration testing only)");
#endif
        ;
        // Add hidden ip and port options.  You technically can use the `--ip=` and `--port=` with
        // these here, but they are meant to be positional.  More usefully, you can specify `ip=`
        // and `port=` in the config file to specify them.
    hidden.add_options()
        ("ip", po::value<std::string>(), "(unused)")
        ("port", po::value(&options_.port), "Port to listen on")
        ("oxend-rpc-ip", po::value(&old_rpc_ip), "Obsolete: oxend HTTP RPC IP; use --oxend-rpc with the zmq address instead")
        ("oxend-rpc-port", po::value(&old_rpc_port), "Obsolete: oxend HTTP RPC port; use --oxend-rpc with the zmq address instead")
        ("lokid-rpc-ip", po::value(&old_rpc_ip), "Backwards compatible option for oxend RPC IP")
        ("lokid-rpc-port", po::value(&old_rpc_port), "Backwards compatible option for oxend RPC port")
        ;
    // clang-format on

    all.add(desc_).add(hidden);
    po::positional_options_description pos_desc;
    pos_desc.add("ip", 1);
    pos_desc.add("port", 1);

    binary_name_ = fs::u8path(argv[0]).filename().u8string();

    po::variables_map vm;

    po::store(po::command_line_parser(argc, argv)
                  .options(all)
                  .positional(pos_desc)
                  .run(),
              vm);
    po::notify(vm);

    fs::path config_path{!config_file.empty()
       ? fs::u8path(config_file)
       : fs::u8path(options_.data_dir) / "storage-server.conf"};

    if (fs::exists(config_path)) {
        po::store(po::parse_config_file<char>(config_path.u8string().c_str(), all), vm);
        po::notify(vm);
    } else if (vm.count("config-file")) {
        throw std::runtime_error(
            "path provided in --config-file does not exist");
    }

    if (options_.print_version || options_.print_help) {
        return;
    }

    if (options_.testnet && !vm.count("oxend-rpc")) {
        options_.oxend_omq_rpc = "ipc://" + (home / ".oxen" / "testnet" / "oxend.sock").u8string();
    }

    if (!vm.count("oxend-rpc") && (!old_rpc_ip.empty() || old_rpc_port != 0)) {
        // If oxend-rpc is specified then just ignore the old values; we really should warn, but the
        // logging system isn't initialized yet.
        throw std::runtime_error{
            "--oxend-rpc-ip/--oxend-rpc-port are obsolete: use --oxend-rpc "
            "with the OMQ RPC address instead"
        };
    }

    if (!vm.count("lmq-port")) {
        throw std::runtime_error(
            "lmq-port command line option is not specified");
    }

    if (!vm.count("ip") || !vm.count("port")) {
        throw std::runtime_error(
            "Invalid option: address and/or port missing.");
    }
}

void command_line_parser::print_usage() const {
    std::cerr << "Usage: " << binary_name_ << " <address> <port> [...]\n\n";

    desc_.print(std::cerr);

    std::cerr << std::endl;

    print_log_levels();
}
} // namespace oxen
