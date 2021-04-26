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
    VERSION 2.1.0
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

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(BUILD_STATIC_DEPS "Download, build and statically link against core dependencies" OFF)
if(BUILD_STATIC_DEPS)
  include(StaticBuild)
else()
  find_package(PkgConfig REQUIRED)
  find_package(Boost REQUIRED system program_options)
  find_package(OpenSSL REQUIRED)
endif()

if(NOT TARGET sodium)
  # Allow -D DOWNLOAD_SODIUM=FORCE to download without even checking for a local libsodium
  option(DOWNLOAD_SODIUM "Allow libsodium to be downloaded and built locally if not found on the system" OFF)
  if(NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM libsodium>=1.0.18 IMPORTED_TARGET)
  endif()

  add_library(sodium INTERFACE)
  if(SODIUM_FOUND AND NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  else()
    if(NOT DOWNLOAD_SODIUM AND NOT BUILD_STATIC_DEPS)
      message(FATAL_ERROR "Could not find libsodium >= 1.0.18; either install it on your system or use -DDOWNLOAD_SODIUM=ON to download and build an internal copy")
    endif()
    message(STATUS "Sodium >= 1.0.18 not found, but DOWNLOAD_SODIUM specified, so downloading it")
    include(DownloadLibSodium)
    target_link_libraries(sodium INTERFACE sodium_vendor)
  endif()

  # Need this target export so that loki-mq properly picks up sodium
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

include(cmake/check_for_std_filesystem.cmake)

if(NOT BUILD_STATIC_DEPS)
endif()

add_subdirectory(common)
add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(httpserver)



option(FORCE_OXENMQ_SUBMODULE "force using oxenmq submodule" OFF)
if(NOT FORCE_OXENMQ_SUBMODULE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(OXENMQ liboxenmq>=1.2.5)
endif()
if(OXENMQ_FOUND)
  add_library(oxenmq INTERFACE)
  link_dep_libs(oxenmq INTERFACE "${OXENMQ_LIBRARY_DIRS}" ${OXENMQ_LIBRARIES})
  target_include_directories(oxenmq INTERFACE ${OXENMQ_INCLUDE_DIRS})
  add_library(oxenmq::oxenmq ALIAS oxenmq)
  message(STATUS "Found system liboxenmq ${OXENMQ_VERSION}")
else()
  message(STATUS "using oxenmq submodule")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries") # Tells oxen-mq to do a static build
  add_subdirectory(vendors/loki-mq)
endif()

if (BUILD_TESTS)
    add_subdirectory(unit_test)
endif ()

include(cmake/archive.cmake)
