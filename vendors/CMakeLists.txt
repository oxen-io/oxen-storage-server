
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
  pkg_check_modules(SPDLOG spdlog>=1.8 IMPORTED_TARGET)
endif()
if(SPDLOG_FOUND)
  add_library(spdlog INTERFACE)
  target_link_libraries(spdlog INTERFACE PkgConfig::SPDLOG)
  add_library(spdlog::spdlog ALIAS spdlog)
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

option(FORCE_OXENC_SUBMODULE "force using oxenc submodule" OFF)
if(NOT STATIC AND NOT FORCE_OXENC_SUBMODULE)
  pkg_check_modules(OXENC liboxenc>=1.0.1 IMPORTED_TARGET)
endif()
if(OXENC_FOUND)
  add_library(oxenc INTERFACE)
  target_link_libraries(oxenc INTERFACE PkgConfig::OXENC)
  add_library(oxenc::oxenc ALIAS oxenc)
  message(STATUS "Found system liboxenc ${OXENC_VERSION}")
else()
  set(WITH_TESTS OFF CACHE BOOL "disable oxenc tests")
  message(STATUS "using oxenc submodule")
  add_subdirectory(oxenc)
  add_library(oxenc::oxenc ALIAS oxenc)
endif()

option(FORCE_OXENMQ_SUBMODULE "force using oxenmq submodule" OFF)
if(NOT STATIC AND NOT FORCE_OXENMQ_SUBMODULE)
  pkg_check_modules(OXENMQ liboxenmq>=1.2.6 IMPORTED_TARGET)
endif()
if(OXENMQ_FOUND)
  add_library(oxenmq INTERFACE)
  target_link_libraries(oxenmq INTERFACE PkgConfig::OXENMQ)
  add_library(oxenmq::oxenmq ALIAS oxenmq)
  message(STATUS "Found system liboxenmq ${OXENMQ_VERSION}")
else()
  message(STATUS "using oxenmq submodule")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries") # Tells oxen-mq to do a static build
  add_subdirectory(oxen-mq)
endif()

set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
add_subdirectory(nlohmann_json)


add_library(oxen-crypto-ops STATIC
  oxen/crypto-ops/keccak.c
  oxen/crypto-ops/hash-ops.c)
target_include_directories(oxen-crypto-ops PUBLIC .)


# uSockets doesn't really have a proper build system (just a very simple Makefile) so build it
# ourselves.
if (NOT CMAKE_VERSION VERSION_LESS 3.12)
    set(conf_depends "CONFIGURE_DEPENDS")
else()
    set(conf_depends "")
endif()
file(GLOB usockets_src ${conf_depends}
    uWebSockets/uSockets/src/*.c
    uWebSockets/uSockets/src/eventing/*.c
    uWebSockets/uSockets/src/crypto/*.c
    uWebSockets/uSockets/src/crypto/*.cpp)
file(COPY uWebSockets/uSockets/src/libusockets.h DESTINATION uWebSockets)
add_library(uSockets STATIC EXCLUDE_FROM_ALL ${usockets_src})
target_include_directories(uSockets PRIVATE uWebSockets/uSockets/src)
target_compile_definitions(uSockets PRIVATE LIBUS_USE_OPENSSL)
target_compile_features(uSockets PRIVATE c_std_11 cxx_std_17)
target_link_libraries(uSockets OpenSSL::SSL OpenSSL::Crypto)

# On Windows uSockets uses libuv for its event loop; on Mac kqueue is the default, but that seems to
# not be reliable on older macos versions (like 10.12), so we use libuv on macos as well.
if (WIN32 OR (APPLE AND NOT IOS))
  if(BUILD_STATIC_DEPS)
    target_link_libraries(uSockets libuv)
  else()
    if(STATIC)
      pkg_check_modules(LIBUV libuv-static REQUIRED IMPORTED_TARGET)
    else()
      pkg_check_modules(LIBUV libuv REQUIRED IMPORTED_TARGET)
    endif()
    target_link_libraries(uSockets PkgConfig::LIBUV)
  endif()
endif()


# The uWebSockets C++ layer is header-only but isn't actually prefixed in the repository itself, but
# rather only on install (which, as above, is just a very simple Makefile).  This is unfortunate
# because it means that we can't use `#include <uWebSockets/App.h>` directly with the repo; so
# instead we emulate the installation process into the build directory and include it (with the
# prefix) from there.
file(COPY uWebSockets/src/ DESTINATION uWebSockets/uWebSockets FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/uWebSockets)
target_link_libraries(uWebSockets INTERFACE uSockets)
target_compile_definitions(uWebSockets INTERFACE UWS_HTTPRESPONSE_NO_WRITEMARK UWS_NO_ZLIB)

# cpr configuration.  Ideally we'd just do this via add_subdirectory, but cpr's cmake requires
# 3.15+, and we target lower than that (and this is fairly simple to build).

if(NOT BUILD_STATIC_DEPS)
  find_package(CURL REQUIRED COMPONENTS HTTP HTTPS SSL)

  # CURL::libcurl wasn't added to FindCURL until cmake 3.12, so add it if necessary
  if (CMAKE_VERSION VERSION_LESS 3.12 AND NOT TARGET CURL::libcurl)
    add_library(libcurl UNKNOWN IMPORTED GLOBAL)
    set_target_properties(libcurl PROPERTIES
      IMPORTED_LOCATION ${CURL_LIBRARIES}
      INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIRS}")
    add_library(CURL_libcurl INTERFACE)
    target_link_libraries(CURL_libcurl INTERFACE libcurl)
    add_library(CURL::libcurl ALIAS CURL_libcurl)
  endif()
endif()

file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)

add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
target_link_libraries(cpr PUBLIC CURL::libcurl)
target_include_directories(cpr PUBLIC cpr/include)
target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
add_library(cpr::cpr ALIAS cpr)


option(USE_JEMALLOC "Link to jemalloc for memory allocations, if found" ON)
add_library(jemalloc INTERFACE)
add_library(jemalloc::jemalloc ALIAS jemalloc)
if (USE_JEMALLOC AND NOT STATIC)
  pkg_check_modules(JEMALLOC jemalloc IMPORTED_TARGET)
  if(JEMALLOC_FOUND)
    target_link_libraries(jemalloc INTERFACE PkgConfig::JEMALLOC)
  endif()
endif()

if(NOT BUILD_STATIC_DEPS) # Under BUILD_STATIC_DEPS the SQLite::SQLite3 target is already set up
  # We require 3.35.x for some queries we use (such as "RETURNING"), and 3.35.5 for bug fixes, but
  # that release is very new as of this writing so we build a static release if the system one is
  # too old.
  pkg_check_modules(SQLite3 sqlite3>=3.35.5 IMPORTED_TARGET)

  if(SQLite3_FOUND)
    add_library(SQLite::SQLite3 ALIAS PkgConfig::SQLite3)
  else()
    include(ExternalProject)
    unset(SQLITE3_VERSION CACHE)
    include(sqlite3_source)

    set(sqlite_urls)
    foreach(mirror ${SQLITE3_MIRROR})
      list(APPEND sqlite_urls "${mirror}/${SQLITE3_SOURCE}")
    endforeach()

    set(deps_cc "${CMAKE_C_COMPILER}")
    if(CMAKE_C_COMPILER_LAUNCHER)
      set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
    endif()
    set(deps_CFLAGS "-O2")
    if(USE_LTO AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
      # For unknown reasons, clang has trouble linking sqlite3 if we build it with lto
      set(deps_CFLAGS "${deps_CFLAGS} -flto")
    endif()

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/include ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/lib)
    ExternalProject_Add(sqlite3_external
      BUILD_IN_SOURCE ON
      PREFIX ${CMAKE_CURRENT_BINARY_DIR}/sqlite3
      URL ${sqlite_urls}
      URL_HASH ${SQLITE3_HASH}
      DOWNLOAD_NO_PROGRESS ON
      CONFIGURE_COMMAND ./configure --disable-shared --prefix=${CMAKE_CURRENT_BINARY_DIR}/sqlite3 --with-pic "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}"
      BUILD_COMMAND true
      INSTALL_COMMAND make install-includeHEADERS install-libLTLIBRARIES
      BUILD_BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/lib/libsqlite3.a ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/include/sqlite3.h
      )
    add_library(SQLite::SQLite3 STATIC IMPORTED GLOBAL)
    add_dependencies(SQLite::SQLite3 sqlite3_external)
    set_target_properties(SQLite::SQLite3 PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/lib/libsqlite3.a)
    target_include_directories(SQLite::SQLite3 INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/include)
  endif()
endif()

# Hack around SQLiteCpp's attempts to locate sqlite3 because we *don't* want to link against the
# system one, but don't download and build the embedded one until build time.  Thankfully it
# actually links against the SQLite::SQLite3 cmake target if it already exists, so all we have to do
# is set that up and circumvent some of the non-target bits of its FindSQLite3.cmake.
set(SQLite3_FOUND TRUE CACHE BOOL "" FORCE)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ignored")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ignored/sqlite3.h" "#define SQLITE_VERSION \"${SQLite3_VERSION}\"")
set(SQLite3_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/ignored" CACHE STRING "" FORCE)
set(SQLite3_LIBRARY "ignored" CACHE STRING "" FORCE)
set(SQLITECPP_INTERNAL_SQLITE OFF CACHE BOOL "don't build SQLiteCpp's internal sqlite3" FORCE)
set(SQLITE_ENABLE_COLUMN_METADATA OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_DOXYGEN OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory(SQLiteCpp)
