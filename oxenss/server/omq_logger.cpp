#include <oxenmq/oxenmq.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>

namespace oxenss {

static auto logcat = log::Cat("omq");

static constexpr std::string_view omq_log_format = "[{}:{}]: {}";
static constexpr std::string_view access_denied_ping = "Access denied to sn.ping";

void omq_logger(oxenmq::LogLevel level, const char* file, int line, std::string message) {
    // Downgrade warnings about sn.ping because there are broken nodes out there that don't know
    // they are broken and try to ping the network, filling up logs pointlessly.
    if (util::starts_with(message, access_denied_ping))
        level = oxenmq::LogLevel::debug;

    switch (level) {
        case oxenmq::LogLevel::fatal:
            log::critical(logcat, omq_log_format, file, line, message);
            break;
        case oxenmq::LogLevel::error:
            log::error(logcat, omq_log_format, file, line, message);
            break;
        case oxenmq::LogLevel::warn:
            log::warning(logcat, omq_log_format, file, line, message);
            break;
        case oxenmq::LogLevel::info: log::info(logcat, omq_log_format, file, line, message); break;
        case oxenmq::LogLevel::debug:
            log::debug(logcat, omq_log_format, file, line, message);
            break;
        case oxenmq::LogLevel::trace:
            log::trace(logcat, omq_log_format, file, line, message);
            break;
    }
}

}  // namespace oxenss
