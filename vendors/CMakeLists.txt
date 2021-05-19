
if(BUILD_STATIC_DEPS)
  set(DEFAULT_STATIC ON)
else()
  set(DEFAULT_STATIC OFF)
endif()
option(STATIC "Try to link external dependencies statically, where possible" ${DEFAULT_STATIC})


if(NOT STATIC AND NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
endif()

option(FORCE_SPDLOG_SUBMODULE "force using spdlog submodule" OFF)
if(NOT STATIC AND NOT FORCE_SPDLOG_SUBMODULE)
  pkg_check_modules(SPDLOG libspdlog>=1.8 IMPORTED_TARGET)
endif()
if(SPDLOG_FOUND)
  add_library(spdlog INTERFACE)
  target_link_libraries(spdlog PkgConfig::SPDLOG)
else()
  add_subdirectory(spdlog)
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

  # Need this target export so that oxenmq properly picks up sodium
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

option(FORCE_OXENMQ_SUBMODULE "force using oxenmq submodule" OFF)
if(NOT STATIC AND NOT FORCE_OXENMQ_SUBMODULE)
  pkg_check_modules(OXENMQ liboxenmq>=1.2.5 IMPORTED_TARGET)
endif()
if(OXENMQ_FOUND)
  add_library(oxenmq INTERFACE)
  target_link_libraries(oxenmq INTERFACE PkgConfig::OXENMQ)
  add_library(oxenmq::oxenmq ALIAS oxenmq)
  message(STATUS "Found system liboxenmq ${OXENMQ_VERSION}")
else()
  message(STATUS "using oxenmq submodule")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries") # Tells oxen-mq to do a static build
  add_subdirectory(loki-mq)
endif()

set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
add_subdirectory(nlohmann_json)


add_library(oxen-crypto-ops STATIC
  oxen/crypto-ops/keccak.c
  oxen/crypto-ops/hash-ops.c)
target_include_directories(oxen-crypto-ops PUBLIC .)


