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

if (INTEGRATION_TEST)
    add_definitions(-DDISABLE_POW)
    add_definitions(-DINTEGRATION_TEST)
endif()

option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication"
    ON)

if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

loki_add_subdirectory(utils)
loki_add_subdirectory(crypto)
loki_add_subdirectory(pow)
loki_add_subdirectory(storage)
loki_add_subdirectory(httpserver)

if (BUILD_TESTS)
    loki_add_subdirectory(unit_test)
endif ()