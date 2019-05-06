cmake_minimum_required(VERSION 3.1)

project(crypto)

set(CMAKE_CXX_STANDARD 11)
set(CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/lokid_key.cpp
    include/lokid_key.h
    include/channel_encryption.hpp
    src/channel_encryption.cpp
    src/signature.cpp
    include/signature.h
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/loki/crypto-ops/crypto-ops.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/loki/crypto-ops/crypto-ops-data.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/loki/crypto-ops/crypto-ops.h
)

add_library(crypto STATIC ${SOURCES})

if (NOT OPENSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif ()
target_link_libraries(crypto PRIVATE OpenSSL::SSL)

target_include_directories(crypto
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/../vendors
)

loki_add_subdirectory(../utils utils)

target_link_libraries(crypto PUBLIC utils)

if (NOT Boost_FOUND)
    find_package(Boost REQUIRED system filesystem)
endif()

target_include_directories(crypto PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(crypto PRIVATE ${Boost_LIBRARIES})

add_executable(crypto_test src/test_main.cpp)
target_link_libraries(crypto_test PRIVATE crypto)

# sodium
list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../contrib")
set(sodium_USE_STATIC_LIBS ON)
find_package(sodium REQUIRED)
target_link_libraries(crypto PUBLIC sodium)

if (UNIX AND NOT APPLE)
    target_link_libraries(crypto PUBLIC pthread dl)
endif ()
