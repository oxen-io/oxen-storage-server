cmake_minimum_required(VERSION 3.1)

function(LOKI_ADD_SUBDIRECTORY SRC)
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

if (INTEGRATION_TEST)
    add_definitions(-DDISABLE_POW)
    add_definitions(-DINTEGRATION_TEST)
endif()


if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/contrib")
set(sodium_USE_STATIC_LIBS ON)
find_package(sodium REQUIRED)
include_directories(${sodium_INCLUDE_DIR})

include_directories("${CMAKE_CURRENT_LIST_DIR}/vendors/loki-mq/cppzmq")
include_directories("${CMAKE_CURRENT_LIST_DIR}/vendors/loki-mq/mapbox-variant/include")

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
