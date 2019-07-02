#pragma once

#include <iostream>

#ifndef STORAGE_SERVER_VERSION
#define STORAGE_SERVER_VERSION 0010
#endif

#ifndef STORAGE_SERVER_VERSION_STRING
#define STORAGE_SERVER_VERSION_STRING "0.1"
#endif

#ifndef STORAGE_SERVER_GIT_HASH_STRING
#define STORAGE_SERVER_GIT_HASH_STRING "?"
#endif

#ifndef STORAGE_SERVER_BUILD_TIME
#define STORAGE_SERVER_BUILD_TIME "?"
#endif

static void print_version() {
    std::cout << "Loki Storage Server v" << STORAGE_SERVER_VERSION_STRING
              << std::endl
              << " git commit hash: " << STORAGE_SERVER_GIT_HASH_STRING
              << std::endl
              << " build time: " << STORAGE_SERVER_BUILD_TIME << std::endl;
}