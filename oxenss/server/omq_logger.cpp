#include <oxenmq/oxenmq.h>
#include <oxenss/logging/oxen_logger.h>

namespace oxen {

static auto logcat = log::Cat("omq");

void omq_logger(oxenmq::LogLevel level, const char* file, int line, std::string message) {
    constexpr std::string_view format = "[{}:{}]: {}";
    switch (level) {
        case oxenmq::LogLevel::fatal: log::critical(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::error: log::error(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::warn: log::warning(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::info: log::info(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::debug: log::debug(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::trace: log::trace(logcat, format, file, line, message); break;
    }
}

}  // namespace oxen
