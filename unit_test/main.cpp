#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <chrono>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

using namespace std::literals;

int main(int argc, char* argv[]) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_st>();
    auto logger = std::make_shared<spdlog::logger>("oxen_logger", console_sink);
    spdlog::register_logger(logger);
    spdlog::flush_every(1s);

    return Catch::Session().run(argc, argv);
}
