# Source version, download location, hash for sqlite3.
#
# This gets used both in the full StaticBuild code *and* in the general build code when the system
# sqlite3 version is too old.

set(SQLITE3_VERSION "3450000" CACHE STRING "sqlite3 version")
set(SQLITE3_MIRROR ${LOCAL_MIRROR} https://www.sqlite.org/2024
    CACHE STRING "sqlite3 download mirror(s)")
set(SQLITE3_SOURCE sqlite-autoconf-${SQLITE3_VERSION}.tar.gz)
set(SQLITE3_HASH SHA512=40ae9ba1dea234aacfecf44a6b1c0713c24348d8d475503c11f1d92ed2fffb54a765bbd0669f39aa09d20f42cbcfac4dedcf7e64f4421b8762eebfc66399aa9a
    CACHE STRING "sqlite3 source hash")

if(SQLITE3_VERSION MATCHES "^([0-9]+)(0([0-9])|([1-9][0-9]))(0([0-9])|([1-9][0-9]))[0-9][0-9]$")
    set(SQLite3_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_3}${CMAKE_MATCH_4}.${CMAKE_MATCH_6}${CMAKE_MATCH_7}" CACHE STRING "" FORCE)
    mark_as_advanced(SQLite3_VERSION)
    message(STATUS "Building static sqlite3 ${SQLite3_VERSION}")
else()
    message(FATAL_ERROR "Couldn't figure out sqlite3 version from '${SQLITE3_VERSION}'")
endif()
