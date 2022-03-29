
add_library(crypto STATIC
    src/oxend_key.cpp
    src/channel_encryption.cpp
    src/signature.cpp)

target_include_directories(crypto PUBLIC include)

find_package(Threads)

target_link_libraries(crypto
    PUBLIC
    common
    utils
    PRIVATE
    oxen-crypto-ops
    OpenSSL::SSL
    sodium
    Threads::Threads
    ${CMAKE_DL_LIBS})
