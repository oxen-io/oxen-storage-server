add_library(pow STATIC
    src/pow.cpp
)

find_package(OpenSSL REQUIRED)
target_link_libraries(pow PRIVATE OpenSSL::SSL)

target_include_directories(pow
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(pow PRIVATE utils lokimq::lokimq)
