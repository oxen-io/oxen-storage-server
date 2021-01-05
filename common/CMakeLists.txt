cmake_minimum_required(VERSION 3.1)

add_definitions(-DSPDLOG_COMPILED_LIB)

add_library(common STATIC
    src/loki_logger.cpp
)

set_property(TARGET common PROPERTY CXX_STANDARD 17)
set_property(TARGET common PROPERTY CXX_STANDARD_REQUIRED TRUE)

loki_add_subdirectory(../vendors/spdlog spdlog)

target_link_libraries(common PUBLIC spdlog::spdlog Boost::filesystem)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
