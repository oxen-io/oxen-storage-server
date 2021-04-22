#include "command_line.h"

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_AUTO_TEST_SUITE(server_command_line)

BOOST_AUTO_TEST_CASE(it_throws_when_no_args) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_CASE(it_throws_when_no_port) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_CASE(it_throws_when_no_port_with_flag) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "--force-start", "0.0.0.0"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_CASE(it_throws_unknown_arg) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--covfefe"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_CASE(it_parses_help) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "--help"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.print_help, true);
}

BOOST_AUTO_TEST_CASE(it_parses_version) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "--version"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.print_version, true);
}

BOOST_AUTO_TEST_CASE(it_parses_force_start) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--force-start"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.force_start, true);
}

BOOST_AUTO_TEST_CASE(it_parses_ip_and_port) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.ip, "0.0.0.0");
    BOOST_CHECK_EQUAL(options.port, 80);
}

BOOST_AUTO_TEST_CASE(it_throw_with_invalid_port) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0",
                          "8O", // notice the O instead of 0
                          "--lmq-port", "123"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_CASE(it_parses_oxend_rpc) {
    oxen::command_line_parser parser;
    std::array argv = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--oxend-rpc",
        "ipc:///path/to/oxend.sock"};
    BOOST_CHECK_NO_THROW(parser.parse_args(argv.size(),
                                           const_cast<char**>(argv.data())));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.oxend_omq_rpc, "ipc:///path/to/oxend.sock");
}

BOOST_AUTO_TEST_CASE(it_parses_oxend_rpc_tcp) {
    oxen::command_line_parser parser;
    std::array argv = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--oxend-rpc",
        "tcp://127.0.0.2:3456"};
    BOOST_CHECK_NO_THROW(parser.parse_args(argv.size(),
                                           const_cast<char**>(argv.data())));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.oxend_omq_rpc, "tcp://127.0.0.2:3456");
}

BOOST_AUTO_TEST_CASE(it_parses_data_dir) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--data-dir",
                          "foobar"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.data_dir, "foobar");
}

BOOST_AUTO_TEST_CASE(it_returns_default_data_dir) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.data_dir, "");
}

BOOST_AUTO_TEST_CASE(it_parses_log_levels) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--log-level",
                          "foobar"};
    BOOST_CHECK_NO_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                           const_cast<char**>(argv)));
    const auto options = parser.get_options();
    BOOST_CHECK_EQUAL(options.log_level, "foobar");
}

BOOST_AUTO_TEST_CASE(it_throws_with_config_file_not_found) {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "0.0.0.0", "80", "--lmq-port", "123", "--config-file",
                          "foobar"};
    BOOST_CHECK_THROW(parser.parse_args(sizeof(argv) / sizeof(char*),
                                        const_cast<char**>(argv)),
                      std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
