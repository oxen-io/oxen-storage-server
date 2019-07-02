#include "command_line.h"
#include "loki_logger.h"

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>

#include <iostream>

namespace loki {

namespace po = boost::program_options;
namespace fs = boost::filesystem;

static void print_usage(const po::options_description& desc,
                        const std::string& binary_name) {

    std::cerr << std::endl;
    std::cerr << "Usage: " << binary_name << " <address> <port> [...]\n\n";

    desc.print(std::cerr);

    std::cerr << std::endl;
    print_log_levels();
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

bool command_line_parser::early_exit() const { return early_exit_; }

const command_line_options& command_line_parser::get_options() const {
    return options_;
}

void command_line_parser::parse_args(int argc, char* argv[]) {
    std::string config_file;
    po::options_description all, desc, hidden;
    // clang-format off
    desc.add_options()
        ("lokid-key", po::value(&options_.lokid_key_path), "Path to the Service Node key file")
        ("data-dir", po::value(&options_.data_dir), "Path to persistent data (defaults to ~/.loki/storage)")
        ("config-file", po::value(&config_file), "Path to custom config file (defaults to `storage-server.conf' inside --data-dir)")
        ("log-level", po::value(&options_.log_level), "Log verbosity level, see Log Levels below for accepted values")
        ("lokid-rpc-port", po::value(&options_.lokid_rpc_port), "RPC port on which the local Loki daemon is listening")
        ("force-start", po::bool_switch(&options_.force_start), "Ignore the initialisation ready check")
        ("version,v", po::bool_switch(&options_.print_version), "Print the version of this binary")
        ("help", "Shows this help message");
        // Add hidden ip and port options.  You technically can use the `--ip=` and `--port=` with
        // these here, but they are meant to be positional.  More usefully, you can specify `ip=`
        // and `port=` in the config file to specify them.
    hidden.add_options()
        ("ip", po::value(&options_.ip), "IP to listen on")
        ("port", po::value(&options_.port), "Port to listen on");
    // clang-format on

    all.add(desc).add(hidden);
    po::positional_options_description pos_desc;
    pos_desc.add("ip", 1);
    pos_desc.add("port", 1);

    std::string binary_name = fs::basename(argv[0]);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv)
                      .options(all)
                      .positional(pos_desc)
                      .run(),
                  vm);
        po::notify(vm);
    } catch (const boost::program_options::error& e) {
        std::cerr << "Invalid options: " << e.what() << std::endl;
        print_usage(desc, binary_name);
        throw;
    }

    if (config_file.empty()) {
        config_file =
            (fs::path(options_.data_dir) / "storage-server.conf").string();
    }
    if (fs::exists(config_file)) {
        try {
            po::store(po::parse_config_file<char>(config_file.c_str(), all),
                      vm);
            po::notify(vm);
        } catch (const boost::program_options::error& e) {
            std::cerr << "Invalid options in config file: " << e.what()
                      << std::endl;
            print_usage(desc, binary_name);
            throw;
        }
    }

    if (vm.count("data-dir")) {
        if (auto home_dir = get_home_dir()) {
            options_.data_dir = (home_dir.get() / ".loki" / "storage").string();
        }
    }

    if (options_.print_version) {
        early_exit_ = true;
        return;
    }

    if (vm.count("help")) {
        print_usage(desc, binary_name);
        early_exit_ = true;
        return;
    }

    if (!vm.count("ip") || !vm.count("port")) {
        print_usage(desc, binary_name);
        throw std::exception();
    }
}
} // namespace loki
