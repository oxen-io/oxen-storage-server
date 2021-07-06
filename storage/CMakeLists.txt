cmake_minimum_required(VERSION 3.5)

add_library(storage STATIC
    src/Database.cpp
)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(storage PRIVATE common utils)
target_link_libraries(storage PRIVATE SQLiteCpp)
