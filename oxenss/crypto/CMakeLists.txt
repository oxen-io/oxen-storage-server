
add_library(crypto STATIC
    keys.cpp
    channel_encryption.cpp
    signature.cpp)

find_package(Threads)

target_link_libraries(crypto
    PRIVATE
    common
    logging
    oxen-crypto-ops
    OpenSSL::SSL
    sodium)
