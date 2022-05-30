#include "oxen_logger.h"

#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/pattern_formatter.h"
#include "dev_sink.h"
#include <filesystem>

#include <cstdlib>
#include <fstream>
#include <iostream>

namespace oxen::logging {

using namespace std::literals;

static constexpr std::array<std::pair<std::string_view, spdlog::level::level_enum>, 6> logLevels = {
        {{"trace"sv, LogLevel::trace},
         {"debug", LogLevel::debug},
         {"info", LogLevel::info},
         {"warning", LogLevel::warn},
         {"error", LogLevel::err},
         {"critical", LogLevel::critical}}};

std::optional<spdlog::level::level_enum> parse_level(std::string_view input) {
    for (const auto& [str, lvl] : logLevels)
        if (str == input)
            return lvl;
    return std::nullopt;
}

void print_levels() {
    std::cerr << "  Log Levels:\n";
    for (const auto& [str, lvl] : logLevels)
        std::cerr << "    " << str << "\n";
}

namespace {
    // We print time elapsed since this time in the log for convenience
    const auto logging_t0 = std::chrono::steady_clock::now();

    class time_since_start_flag : public spdlog::custom_flag_formatter {
      public:
        void format(const spdlog::details::log_msg&, const std::tm&, spdlog::memory_buf_t& dest)
                override {
            using namespace std::literals;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - logging_t0);
            auto h = std::chrono::duration_cast<std::chrono::hours>(ms);
            ms -= h;
            auto m = std::chrono::duration_cast<std::chrono::minutes>(ms);
            ms -= m;
            auto s = std::chrono::duration_cast<std::chrono::seconds>(ms);
            ms -= s;
            std::string elapsed;
            if (h > 0h)
                elapsed = fmt::format(
                        "{}h{:02d}m{:02d}.{:03d}s", h.count(), m.count(), s.count(), ms.count());
            else if (m > 0min)
                elapsed = fmt::format("{}m{:02d}.{:03d}s", m.count(), s.count(), ms.count());
            else
                elapsed = fmt::format("{}.{:03d}s", s.count(), ms.count());

            dest.append(elapsed.data(), elapsed.data() + elapsed.size());
        }

        std::unique_ptr<custom_flag_formatter> clone() const override {
            return spdlog::details::make_unique<time_since_start_flag>();
        }
    };

}  // namespace

void init(const std::filesystem::path& data_dir, LogLevel log_level) {
    const std::string log_location = (data_dir / "storage.logs").u8string();
    // Log to disk output stream
    const auto input = std::shared_ptr<std::ofstream>(
            new std::ofstream(log_location, std::ios::out | std::ios::app));
    if (input->is_open()) {
        input->close();
    } else {
        std::cerr << "Could not open " << log_location << std::endl;
        return;
    }

    constexpr size_t LOG_FILE_SIZE_LIMIT = 1024 * 1024 * 50;  // 50Mb
    constexpr size_t EXTRA_FILES = 1;

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(log_level);
    console_sink->set_color_mode(spdlog::color_mode::always);

    // setting this to `true` can be useful for debugging on testnet
    bool rotate_on_open = false;

    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_location, LOG_FILE_SIZE_LIMIT, EXTRA_FILES, rotate_on_open);
    file_sink->set_level(log_level);

    auto developer_sink = std::make_shared<logging::dev_sink_mt>();

    /// IMPORTANT: get_logs endpoint assumes that sink #3 is a dev sink
    std::vector<spdlog::sink_ptr> sinks = {console_sink, file_sink, developer_sink};

    auto logger = std::make_shared<spdlog::logger>("oxen_logger", sinks.begin(), sinks.end());
    logger->set_level(log_level);
    logger->flush_on(spdlog::level::err);

    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<time_since_start_flag>('*').set_pattern(
            "[%Y-%m-%d %H:%M:%S/+%*] [%^%l%$] [%s:%#] %v");
    logger->set_formatter(std::move(formatter));

    developer_sink->set_level(spdlog::level::warn);
    spdlog::register_logger(logger);
    spdlog::flush_every(std::chrono::seconds(1));

    OXEN_LOG(info, "\nOutputting logs to {}", log_location);
}
}  // namespace oxen::logging
