#include "command_line.h"
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/version.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <filesystem>
#include <iostream>
#include <optional>

extern "C" {
#include <pwd.h>
#include <unistd.h>

#ifdef __linux__
#include <stdio.h>
#include <sys/ioctl.h>
#endif
}

namespace oxen::cli {

using namespace std::literals;

static std::optional<std::filesystem::path> get_home_dir() {
    char* home = getenv("HOME");
    if (!home || !strlen(home))
        if (const auto* pwd = getpwuid(getuid()))
            home = pwd->pw_dir;

    if (home && strlen(home))
        return std::filesystem::u8path(home);

    return std::nullopt;
}

class WrapFormatter : public CLI::Formatter {
  private:
    size_t term_width_ = 0;

  public:
    WrapFormatter() {
#ifdef __linux__
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
            term_width_ = w.ws_col;
#endif
    }

    // Crude word-wrapping function for long option descriptions; this only applies if we could
    // detect the terminal width (which currently we only implement on linux)
    std::string make_option_desc(const CLI::Option* opt) const override {
        if (term_width_ <= column_width_ + 1)
            return CLI::Formatter::make_option_desc(opt);

        size_t desc_width = term_width_ - column_width_ - 1;

        constexpr auto npos = std::string_view::npos;

        std::string out;
        auto desc = opt->get_description();
        std::string_view d{desc};
        while (!d.empty()) {
            auto chop = npos;
            // If we have a newline in the next chunk of the description then wrap and indent
            // there
            if (auto pos = d.find_first_of('\n');
                pos != npos && pos <= desc_width && pos + 1 < d.size())
                chop = pos;
            // If no newlines and the text is short enough then just send it as-is:
            else if (d.size() <= desc_width)
                chop = npos;
            // Break on space:
            else if (pos = d.find_last_of(' ', desc_width); pos != npos && pos > 0)
                chop = pos;
            // We couldn't find a space anywhere before the end of the term so we'll let it
            // overflow and then break at the next viable place:
            else if (pos = d.find_first_of(" \n"sv); pos != npos)
                chop = pos;

            if (chop == npos) {
                out += d;
                break;
            }
            out += d.substr(0, chop);
            out += "\n";
            d.remove_prefix(chop >= d.size() ? chop : chop + 1);
        }
        return out;
    }
};

namespace fs = std::filesystem;

parse_result parse_cli_args(std::vector<const char*> args) {
    return parse_cli_args(args.size(), const_cast<char**>(args.data()));
}
parse_result parse_cli_args(int argc, char* argv[]) {
    command_line_options options{};

    // This is a bit crude: we have various defaults that change based on whether --testnet is
    // passed or not, so we first do a pass through args to see if it is to set those defaults.
    bool testnet = false;
    for (int i = 1; i < argc; i++) {
        if (argv[i] == "--testnet"sv) {
            testnet = true;
            break;
        }
    }

    CLI::App cli{"Oxen Storage Server"};
    cli.formatter(std::make_shared<WrapFormatter>());

    std::filesystem::path data_dir, testnet_dir;
    auto base_dir = get_home_dir().value_or(fs::current_path());
    if (!(base_dir == fs::path("/var/lib/oxen") || base_dir == fs::path("/var/lib/loki")))
        base_dir /= ".oxen";
    if (testnet) {
        base_dir /= "testnet";
        options.https_port = 38155;
        options.omq_port = 38154;
    }

    options.data_dir = base_dir / "storage";
    options.oxend_omq_rpc = "ipc://" + (base_dir / "oxend.sock").u8string();
    data_dir = base_dir / "storage";

    cli.add_option("--data-dir", options.data_dir, "Path in which to store persistent data")
            ->type_name("DIR")
            ->capture_default_str();
    cli.set_config(
               "--config-file",
               (options.data_dir / "storage-server.conf").u8string(),
               "Path to config file specifying additional command-line options")
            ->capture_default_str();
    cli.add_option(
               "--log-level",
               options.log_level,
               "Log verbosity level, see Log Levels below for accepted values")
            ->type_name("LEVEL")
            ->capture_default_str();
    cli.add_option(
               "--oxend-rpc",
               options.oxend_omq_rpc,
               "OMQ RPC address on which oxend is available; typically "
               "ipc:///path/to/oxend.sock or tcp://localhost:22025")
            ->type_name("OMQ_URL")
            ->capture_default_str();
    cli.add_option(
               "--omq-port,--lmq-port",
               options.omq_port,
               "Public port to listen on for OxenMQ connections")
            ->capture_default_str()
            ->type_name("PORT");
    cli.add_option(
               "--https-port", options.https_port, "Public port to listen on for HTTPS connections")
            ->capture_default_str()
            ->type_name("PORT");
    cli.add_option(
            "ignored",
            [](auto&&) { return true; },
            "Deprecated positional argument; ignored");  // Ignored positional arg, but recognized
                                                         // for backwards compat.
    cli.add_option(
               "--port,port",
               options.https_port,
               "Deprecated port argument; use --https-port option instead")
            ->capture_default_str()
            ->type_name("PORT");
    // TODO: need to support multiple here (e.g. so we can listen on public + lokinet)
    cli.add_option(
               "--bind-ip",
               options.ip,
               "IP address on which to listen for connections; typically this should be the "
               "0.0.0.0 (the IPv4 \"any\" address)")
            ->capture_default_str()
            ->type_name("IP");
    cli.add_flag("--testnet", options.testnet, "Start storage server in testnet mode");
    cli.add_flag(
            "--force-start",
            options.force_start,
            "Ignore the initialisation ready check (primarily for debugging).");
    cli.add_option(
               "--stats-access-key",
               options.stats_access_keys,
               "One or more public keys (x25519) that will be granted access to the "
               "`get_stats` omq endpoint")
            ->type_name("PUBKEY");
    cli.set_version_flag("--version,-v", std::string{oxen::STORAGE_SERVER_VERSION_INFO});

    // Deprecated options, put in the "" group to hide them:
    // Old versions had a janky interface where some options were as above, but for some reason
    // IP and port were positional.  But then IP started getting ignored because we always want
    // to use 0.0.0.0 but then the port was stranded as a second positional argument.  The
    // lovely mess of not using forward-looking design.

    try {
        cli.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return cli.exit(e);
    }

    return options;
}

}  // namespace oxen::cli
