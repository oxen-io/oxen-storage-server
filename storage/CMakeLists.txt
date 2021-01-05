cmake_minimum_required(VERSION 3.5)

add_library(storage STATIC
    src/Database.cpp
)

set_property(TARGET storage PROPERTY CXX_STANDARD 17)
set_property(TARGET storage PROPERTY CXX_STANDARD_REQUIRED TRUE)

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


if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

target_link_libraries(storage PRIVATE Boost::system Boost::filesystem)
