cmake_minimum_required(VERSION 3.1)

add_definitions(-DSPDLOG_COMPILED_LIB)

add_library(common STATIC
    src/oxen_logger.cpp
)

add_subdirectory(../vendors/spdlog spdlog)
target_link_libraries(common PUBLIC spdlog::spdlog filesystem oxenmq::oxenmq)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
