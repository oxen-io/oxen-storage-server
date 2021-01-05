cmake_minimum_required(VERSION 3.5)

add_library(storage STATIC
    src/Database.cpp
)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

loki_add_subdirectory(../common common)
target_link_libraries(storage PRIVATE common)
loki_add_subdirectory(../utils utils)
target_link_libraries(storage PRIVATE utils)
loki_add_subdirectory(../vendors/sqlite sqlite)
target_link_libraries(storage PRIVATE sqlite)

target_link_libraries(storage PRIVATE Boost::boost)
