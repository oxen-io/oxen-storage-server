set(SOURCES
    include/pow.hpp
    src/pow.cpp
    src/base64.cpp
    src/base64.hpp
)

add_library(pow STATIC ${SOURCES})

find_package(OpenSSL REQUIRED)
target_link_libraries(pow PRIVATE OpenSSL::SSL)

target_include_directories(pow
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
