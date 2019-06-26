cmake_minimum_required(VERSION 3.1)

set(SOURCES
    include/Database.hpp
    include/Item.hpp
    src/Database.cpp
)

add_library(storage STATIC ${SOURCES})

set_property(TARGET storage PROPERTY CXX_STANDARD 14)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/spdlog/include
)

loki_add_subdirectory(../utils utils)
target_link_libraries(storage PRIVATE utils)
loki_add_subdirectory(../vendors/sqlite sqlite)
target_link_libraries(storage PRIVATE sqlite)

loki_add_subdirectory(../vendors/spdlog spdlog)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

target_include_directories(storage PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(storage PRIVATE ${Boost_LIBRARIES})
