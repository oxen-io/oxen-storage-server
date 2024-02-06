
add_library(common STATIC
    namespace.cpp
    pubkey.cpp
)

target_link_libraries(common PUBLIC oxen::logging oxenss_filesystem oxenc::oxenc)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
