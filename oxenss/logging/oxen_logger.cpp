#include "oxen_logger.h"
#include <oxen/log.hpp>
#include <fmt/std.h>

#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>

namespace oxen::logging {

static auto logcat = oxen::log::Cat("logging");

void init(const std::filesystem::path& data_dir, oxen::log::Level log_level) {

    log::reset_level(log_level);
    log::add_sink(log::Type::Print, "stdout");

    auto log_location = data_dir / "storage.logs";

    constexpr size_t LOG_FILE_SIZE_LIMIT = 1024 * 1024 * 50;  // 50MiB
    constexpr size_t EXTRA_FILES = 1;

    // setting this to `true` can be useful for debugging on testnet
    bool rotate_on_open = false;

    try {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_location, LOG_FILE_SIZE_LIMIT, EXTRA_FILES, rotate_on_open);

        log::add_sink(std::move(file_sink));
    } catch (const spdlog::spdlog_ex& ex) {
        log::error(
                logcat,
                "Failed to open {} for logging: {}.  File logging disabled.",
                log_location,
                ex.what());
        return;
    }

    log::info(logcat, "Writing logs to {}", log_location);
}

}  // namespace oxen::logging
