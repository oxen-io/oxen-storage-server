cmake_minimum_required(VERSION 3.1)

add_library(common STATIC
    src/oxen_common.cpp
    src/oxen_logger.cpp
)

target_link_libraries(common PUBLIC spdlog::spdlog filesystem oxenc::oxenc)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_compile_definitions(common PUBLIC SPDLOG_COMPILED_LIB)

