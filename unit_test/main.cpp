#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include <chrono>

#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"

bool init_unit_test() {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_st>();
    auto logger = std::make_shared<spdlog::logger>("loki_logger", console_sink);
    spdlog::register_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));
    return true;
}
