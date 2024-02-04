#include "oxen_logger.h"
#include <oxen/log.hpp>
#include <fmt/std.h>

#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>

namespace oxenss::logging {

static auto logcat = oxen::log::Cat("logging");

void init(const std::filesystem::path& data_dir, oxen::log::Level log_level) {

    log::reset_level(log_level);

    // QUIC is a bit chatty, and we probably care more about storage server than quic logging, so if
    // we're above trace and below critical, set the log level for the libquic categories to one
    // higher than the general oxenss log level.
    if (log_level > oxen::log::Level::trace && log_level < oxen::log::Level::critical) {
        auto quic_level = static_cast<oxen::log::Level>(
                static_cast<std::underlying_type_t<oxen::log::Level>>(log_level) + 1);
        for (const auto& cat : {"quic", "libevent", "bparser"})
            log::set_level(cat, quic_level);
    }

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

}  // namespace oxenss::logging
