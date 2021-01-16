cmake_minimum_required(VERSION 3.5)

add_library(crypto STATIC
    src/oxend_key.cpp
    src/channel_encryption.cpp
    src/signature.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/oxen/crypto-ops/crypto-ops.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/oxen/crypto-ops/crypto-ops-data.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/oxen/crypto-ops/keccak.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/oxen/crypto-ops/hash-ops.c
)

if (NOT OPENSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif ()
target_link_libraries(crypto PRIVATE OpenSSL::SSL)

target_include_directories(crypto
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../vendors
)

target_link_libraries(crypto PUBLIC utils)

add_executable(crypto_test src/test_main.cpp)
target_link_libraries(crypto_test PRIVATE crypto)

find_package(Threads)

target_link_libraries(crypto PRIVATE
    sodium
    Boost::boost
    lokimq::lokimq
    filesystem
    Threads::Threads
    ${CMAKE_DL_LIBS})
