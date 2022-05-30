
add_library(logging STATIC
    oxen_logger.cpp
)

target_link_libraries(logging PUBLIC spdlog::spdlog)
