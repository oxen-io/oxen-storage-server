#pragma once

#include <boost/program_options.hpp>
#include <string>

namespace oxen {

struct command_line_options {
    uint16_t port;
    std::string oxend_omq_rpc; // Defaults to ipc://$HOME/.oxen/[testnet/]oxend.sock
    uint16_t omq_port;
    bool force_start = false;
    bool print_version = false;
    bool print_help = false;
    bool testnet = false;
    std::string ip;
    std::string log_level = "info";
    std::string data_dir;
    std::string oxend_key; // test only (but needed for backwards compatibility)
    std::string oxend_x25519_key;  // test only
    std::string oxend_ed25519_key; // test only
    // x25519 key that will be given access to get_stats omq endpoint
    std::vector<std::string> stats_access_keys;
};

class command_line_parser {
  public:
    void parse_args(int argc, char* argv[]);
    void parse_args(std::vector<const char*> args);
    bool early_exit() const;

    const command_line_options& get_options() const;
    void print_usage() const;

  private:
    boost::program_options::options_description desc_;
    command_line_options options_;
    std::string binary_name_;
};

} // namespace oxen
