# Source version, download location, hash for sqlite3.
#
# This gets used both in the full StaticBuild code *and* in the general build code when the system
# sqlite3 version is too old.

set(SQLITE3_VERSION "3430101" CACHE STRING "sqlite3 version")
set(SQLITE3_MIRROR ${LOCAL_MIRROR} https://www.sqlite.org/2023
    CACHE STRING "sqlite3 download mirror(s)")
set(SQLITE3_SOURCE sqlite-autoconf-${SQLITE3_VERSION}.tar.gz)
set(SQLITE3_HASH SHA512=d459b1d8ce1036d79545bcef0194de35d3671a1477dbbef3fc94e5beb65e420cf5f3a08ce8f1837d586a16d9b59555691c1fe6351de248839b92bdef0e8d0407
    CACHE STRING "sqlite3 source hash")

if(SQLITE3_VERSION MATCHES "^([0-9]+)(0([0-9])|([1-9][0-9]))(0([0-9])|([1-9][0-9]))[0-9][0-9]$")
    set(SQLite3_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_3}${CMAKE_MATCH_4}.${CMAKE_MATCH_6}${CMAKE_MATCH_7}" CACHE STRING "" FORCE)
    mark_as_advanced(SQLite3_VERSION)
    message(STATUS "Building static sqlite3 ${SQLite3_VERSION}")
else()
    message(FATAL_ERROR "Couldn't figure out sqlite3 version from '${SQLITE3_VERSION}'")
endif()
