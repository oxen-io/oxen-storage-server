#include "command_line.h"

#include <catch2/catch.hpp>

#include <array>

TEST_CASE("command line throws with no arguments", "[cli][no-args]") {
    oxen::command_line_parser parser;
    CHECK_THROWS_AS(
            parser.parse_args({"httpserver"}),
            std::exception);
}

TEST_CASE("port is required", "[cli][port]") {
    {
        oxen::command_line_parser parser;
        CHECK_THROWS_WITH(
                parser.parse_args({"httpserver", "0.0.0.0", "--omq-port", "123"}),
                "Invalid option: address and/or port missing.");
    }
    {
        oxen::command_line_parser parser;
        CHECK_THROWS_WITH(
                parser.parse_args({"httpserver", "--force-start", "0.0.0.0", "--omq-port", "123"}),
                "Invalid option: address and/or port missing.");
    }
}

TEST_CASE("unknown argument", "[cli][unknown-arg]") {
    oxen::command_line_parser parser;
    CHECK_THROWS_WITH(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--covfefe"}),
            "unrecognised option '--covfefe'");
}

TEST_CASE("help", "[cli][help]") {
    oxen::command_line_parser parser;
    const char* argv[] = {"httpserver", "--help"};
    REQUIRE_NOTHROW(parser.parse_args({"httpserver", "--help"}));
    CHECK(parser.get_options().print_help);
}

TEST_CASE("version", "[cli][version]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(parser.parse_args({"httpserver", "--version"}));
    CHECK(parser.get_options().print_version);
}

TEST_CASE("force start", "[cli][force-start]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123", "--force-start"}));
    CHECK(parser.get_options().force_start);
}

TEST_CASE("ip and port", "[cli][ip][port]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123"}));
    const auto options = parser.get_options();
    CHECK(options.ip == "0.0.0.0");
    CHECK(options.port == 80);
}

TEST_CASE("deprecated lmq port", "[cli][deprecated]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--lmq-port", "123"}));
    const auto options = parser.get_options();
    CHECK(options.ip == "0.0.0.0");
    CHECK(options.port == 80);
    CHECK(options.omq_port == 123);
}


TEST_CASE("invalid port", "[cli][port]") {
    oxen::command_line_parser parser;
    CHECK_THROWS_WITH(
            parser.parse_args({"httpserver", "0.0.0.0",
                          "8O", // notice the O instead of 0
                          "--omq-port", "123"}),
            "the argument ('8O') for option '--port' is invalid");

}

TEST_CASE("oxend rpc", "[cli][oxend]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123", "--oxend-rpc",
                "ipc:///path/to/oxend.sock"}));
    CHECK(parser.get_options().oxend_omq_rpc == "ipc:///path/to/oxend.sock");
}

TEST_CASE("oxend rpc -- tcp", "[cli][oxend]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123", "--oxend-rpc",
                "tcp://127.0.0.2:3456"}));
    CHECK(parser.get_options().oxend_omq_rpc == "tcp://127.0.0.2:3456");
}

TEST_CASE("data dir", "[cli][datadir]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123", "--data-dir",
                          "foobar"}));
    CHECK(parser.get_options().data_dir == "foobar");
}

TEST_CASE("default data dir", "[cli][data-dir]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123"}));
    CHECK(parser.get_options().data_dir == "");
}

TEST_CASE("log level", "[cli][log-level]") {
    oxen::command_line_parser parser;
    REQUIRE_NOTHROW(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123",
                "--log-level", "foobar"}));
    CHECK(parser.get_options().log_level == "foobar");
}

TEST_CASE("config not found", "[cli][config]") {
    oxen::command_line_parser parser;
    CHECK_THROWS_WITH(
            parser.parse_args({"httpserver", "0.0.0.0", "80", "--omq-port", "123",
                "--config-file", "foobar"}),
            "path provided in --config-file does not exist");
}
