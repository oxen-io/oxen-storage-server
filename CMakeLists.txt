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

cmake_minimum_required(VERSION 3.10)

project(storage_server
    VERSION 2.2.0
    LANGUAGES CXX C)

option(INTEGRATION_TEST "build for integration test" OFF)
option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication"
    OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

cmake_policy(SET CMP0069 NEW) # Do LTO properly
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
option(USE_LTO "Use Link-Time Optimization" ON)
if(USE_LTO AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO disabled")
  set(IPO_ENABLED OFF)
endif()

if (INTEGRATION_TEST)
    add_definitions(-DINTEGRATION_TEST)
endif()


if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

option(BUILD_TESTS "build storage server unit tests" OFF)

find_package(Git)
option(MANUAL_SUBMODULES "Don't check for out-of-date submodules" OFF)
if(NOT GIT_FOUND)
  message(WARNING "Git not found, unable to check that submodules are up-to-date")
else()
  function (check_submodule relative_path)
    execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE localHead)
    execute_process(COMMAND git rev-parse "HEAD:${relative_path}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} OUTPUT_VARIABLE checkedHead)
    string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
    if (upToDate)
      message(STATUS "Submodule '${relative_path}' is up-to-date")
    elseif(MANUAL_SUBMODULES)
      message(WARNING "Submodule '${relative_path}' is not up-to-date")
    else()
      message(FATAL_ERROR "Submodule '${relative_path}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DMANUAL_SUBMODULES=1")
    endif()

    # Extra arguments check nested submodules
    foreach(submod ${ARGN})
      execute_process(COMMAND git rev-parse "HEAD" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/${submod} OUTPUT_VARIABLE localHead)
      execute_process(COMMAND git rev-parse "HEAD:${submod}" WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${relative_path} OUTPUT_VARIABLE checkedHead)
      string(COMPARE EQUAL "${localHead}" "${checkedHead}" upToDate)
      if (NOT upToDate)
        if(MANUAL_SUBMODULES)
          message(WARNING "Nested submodule '${relative_path}/${submod}' is not up-to-date")
        else()
          message(FATAL_ERROR "Nested submodule '${relative_path}/${submod}' is not up-to-date. Please update with\ngit submodule update --init --recursive\nor run cmake with -DMANUAL_SUBMODULES=1")
        endif()
      endif()
    endforeach()
  endfunction ()

  message(STATUS "Checking submodules")
  check_submodule(vendors/spdlog)
  check_submodule(vendors/oxen-mq cppzmq)
  check_submodule(vendors/nlohmann_json)
  check_submodule(vendors/uWebSockets uSockets)
  check_submodule(vendors/cpr)
  if(BUILD_TESTS)
    check_submodule(unit_test/Catch2)
  endif()
endif()


list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(BUILD_STATIC_DEPS "Download, build and statically link against core dependencies" OFF)
if(BUILD_STATIC_DEPS)
  include(StaticBuild)
else()
  find_package(PkgConfig REQUIRED)
  find_package(Boost REQUIRED program_options)
  find_package(OpenSSL REQUIRED)
endif()

include(cmake/check_atomic.cmake)
link_libatomic()

include(cmake/check_for_std_filesystem.cmake)

add_subdirectory(common)
add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(httpserver)

add_subdirectory(vendors)

if (BUILD_TESTS)
    add_subdirectory(unit_test)
endif ()

include(cmake/archive.cmake)
