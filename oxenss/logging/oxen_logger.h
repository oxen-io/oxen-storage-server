#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"  // for operator<< overload

#define OXEN_LOG_N(LVL, msg, ...)                                              \
    spdlog::get("oxen_logger")                                                 \
            ->log(spdlog::source_loc{__FILE__, __LINE__, __PRETTY_FUNCTION__}, \
                  spdlog::level::LVL,                                          \
                  msg,                                                         \
                  __VA_ARGS__)
#define OXEN_LOG_2(LVL, msg)                                                   \
    spdlog::get("oxen_logger")                                                 \
            ->log(spdlog::source_loc{__FILE__, __LINE__, __PRETTY_FUNCTION__}, \
                  spdlog::level::LVL,                                          \
                  msg)

#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, NAME, ...) NAME
#define OXEN_LOG(...)    \
    GET_MACRO(           \
            __VA_ARGS__, \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_N,  \
            OXEN_LOG_2)  \
    (__VA_ARGS__)

#define OXEN_LOG_ENABLED(LVL) spdlog::get("oxen_logger")->should_log(spdlog::level::LVL)

namespace oxen::logging {

using LogLevel = spdlog::level::level_enum;

void init(const std::filesystem::path& data_dir, LogLevel log_level);

void print_levels();

std::optional<LogLevel> parse_level(std::string_view input);
}  // namespace oxen::logging
