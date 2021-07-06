#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <chrono>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

using namespace std::literals;

class catch_sink : public spdlog::sinks::base_sink<std::mutex> {
    public:
        catch_sink() = default;
        ~catch_sink() override = default;

    protected:
        void sink_it_(const spdlog::details::log_msg& msg) override {
            spdlog::memory_buf_t formatted;
            formatter_->format(msg, formatted);
            UNSCOPED_INFO(std::string_view(formatted.data(), formatted.size()));
        }
        void flush_() override {}
};

int main(int argc, char* argv[]) {
    auto logger = std::make_shared<spdlog::logger>(
            "oxen_logger", std::make_shared<catch_sink>());
    logger->set_level(spdlog::level::debug);
    spdlog::register_logger(logger);

    return Catch::Session().run(argc, argv);
}
