cmake_minimum_required(VERSION 3.1)

project(sn_storage)

set(SOURCES
    include/Storage.hpp
    include/Item.hpp
    src/Storage.cpp
    src/DatabaseHandler.hpp
    src/DatabaseHandler.cpp
    src/Timer.hpp
)

add_library(sn_storage STATIC ${SOURCES})

set_property(TARGET sn_storage PROPERTY CXX_STANDARD 11)

target_include_directories(sn_storage
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_subdirectory(vendor/sqlite)
target_link_libraries(sn_storage PRIVATE sqlite)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

target_include_directories(sn_storage PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(sn_storage PRIVATE ${Boost_LIBRARIES})
