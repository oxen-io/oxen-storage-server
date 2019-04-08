cmake_minimum_required(VERSION 2.8.0)

add_definitions(-DBOOST_LOG_DYN_LINK)
add_definitions(-DDISABLE_ENCRYPTION)

project(httpserver)

set(HEADER_FILES http_connection.h swarm.h service_node.h serialization.h ../external/json.hpp)
set(SRC_FILES main.cpp http_connection.cpp swarm.cpp service_node.cpp serialization.cpp)

add_executable(httpserver ${HEADER_FILES} ${SRC_FILES})

add_subdirectory(../storage storage)
add_subdirectory(../utils utils)
add_subdirectory(../pow pow)
add_subdirectory(../crypto crypto)
find_package(OpenSSL REQUIRED)

find_package(Boost
    REQUIRED
    log
    system
    filesystem
    program_options
)

target_link_libraries(httpserver PRIVATE OpenSSL::SSL)
target_link_libraries(httpserver PRIVATE sn_storage)
target_link_libraries(httpserver PRIVATE utils)
target_link_libraries(httpserver PRIVATE pow)
target_link_libraries(httpserver PRIVATE crypto)

set_property(TARGET httpserver PROPERTY CXX_STANDARD 14)

target_include_directories(httpserver PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(httpserver PRIVATE ${Boost_LIBRARIES})
