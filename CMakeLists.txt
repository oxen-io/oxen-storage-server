cmake_minimum_required(VERSION 3.8)

function(loki_add_subdirectory SRC)
    get_filename_component(target ${SRC} NAME)
    if (TARGET ${target})
        return()
    endif ()
    add_subdirectory(${SRC} ${ARGN})
endfunction()

project(storage_server)

option(INTEGRATION_TEST "build for integration test" OFF)
option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication"
    OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

if (INTEGRATION_TEST)
    add_definitions(-DDISABLE_POW)
    add_definitions(-DINTEGRATION_TEST)
endif()


if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/contrib")
find_package(sodium REQUIRED)
if (sodium_VERSION VERSION_LESS 1.0.17)
  message(FATAL_ERROR "sodium 1.0.17 or higher required; found ${sodium_VERSION}")
endif()
include_directories(${sodium_INCLUDE_DIR})

include(contrib/check_for_std_filesystem.cmake)

find_package(Boost REQUIRED)

loki_add_subdirectory(common)
loki_add_subdirectory(utils)
loki_add_subdirectory(crypto)
loki_add_subdirectory(pow)
loki_add_subdirectory(storage)
loki_add_subdirectory(httpserver)
loki_add_subdirectory(vendors/spdlog)

if (BUILD_TESTS)
    loki_add_subdirectory(unit_test)
endif ()
