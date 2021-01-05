set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

cmake_minimum_required(VERSION 3.8)

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

add_subdirectory(common)
add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(pow)
add_subdirectory(storage)
add_subdirectory(httpserver)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries") # Tells loki-mq to do a static build
add_subdirectory(vendors/loki-mq)

option(BUILD_TESTS "build storage server unit tests" OFF)
if (BUILD_TESTS)
    add_subdirectory(unit_test)
endif ()
