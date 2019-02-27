cmake_minimum_required(VERSION 2.8.0)

project(httpserver)

add_executable(httpserver main.cpp http_connection.hpp)

add_subdirectory(../storage storage)
add_subdirectory(../pow pow)
add_subdirectory(../crypto crypto)


find_package(OpenSSL REQUIRED)

target_link_libraries(httpserver PRIVATE OpenSSL::SSL)
target_link_libraries(httpserver PRIVATE sn_storage)
target_link_libraries(httpserver PRIVATE pow)
target_link_libraries(httpserver PRIVATE crypto)

set_property(TARGET httpserver PROPERTY CXX_STANDARD 11)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

target_include_directories(httpserver PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(httpserver PRIVATE ${Boost_LIBRARIES})
