#include <oxenmq/oxenmq.h>
#include <oxenss/logging/oxen_logger.h>

namespace oxen {

void omq_logger(oxenmq::LogLevel level, const char* file, int line, std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL) \
    case oxenmq::LogLevel::LMQ_LVL: OXEN_LOG(SS_LVL, "[{}:{}]: {}", file, line, message); break;

    switch (level) {
        LMQ_LOG_MAP(fatal, critical);
        LMQ_LOG_MAP(error, err);
        LMQ_LOG_MAP(warn, warn);
        LMQ_LOG_MAP(info, info);
        LMQ_LOG_MAP(trace, trace);
        LMQ_LOG_MAP(debug, debug);
    }
#undef LMQ_LOG_MAP
}

}  // namespace oxen
