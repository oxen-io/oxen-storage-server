# Source version, download location, hash for sqlite3.
#
# This gets used both in the full StaticBuild code *and* in the general build code when the system
# sqlite3 version is too old.

set(SQLITE3_VERSION "3350500" CACHE STRING "sqlite3 version")
set(SQLITE3_MIRROR ${LOCAL_MIRROR} https://www.sqlite.org/2021
    CACHE STRING "sqlite3 download mirror(s)")
set(SQLITE3_SOURCE sqlite-autoconf-${SQLITE3_VERSION}.tar.gz)
set(SQLITE3_HASH SHA512=039af796f79fc4517be0bd5ba37886264d49da309e234ae6fccdb488ef0109ed2b917fc3e6c1fc7224dff4f736824c653aaf8f0a37550c5ebc14d035cb8ac737
    CACHE STRING "sqlite3 source hash")
