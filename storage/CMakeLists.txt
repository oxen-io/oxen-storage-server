cmake_minimum_required(VERSION 3.5)

add_library(storage STATIC
    src/Database.cpp
)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(storage PRIVATE common utils)
if(BUILD_STATIC_DEPS)
  # sqlite3 target already set up
else()
  # We require 3.35.x for some queries we use (such as "RETURNING"), and 3.35.5 for bug fixes, but
  # that release is very new as of this writing so we build a static release if the system one is
  # too old.
  pkg_check_modules(SQLITE3 sqlite3>=3.35.5 IMPORTED_TARGET)

  if(SQLITE3_FOUND)
    add_library(sqlite3 INTERFACE)
    target_link_libraries(sqlite3 INTERFACE PkgConfig::SQLITE3)
  else()
    message(STATUS "Building static sqlite3")
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
    if(USE_LTO)
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
    add_library(sqlite3 STATIC IMPORTED GLOBAL)
    add_dependencies(sqlite3 sqlite3_external)
    set_target_properties(sqlite3 PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/sqlite3/lib/libsqlite3.a)
  endif()
endif()

target_link_libraries(storage PRIVATE sqlite3)
