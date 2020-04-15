if (TARGET utils)
    return()
endif()

add_library(utils STATIC
    src/utils.cpp
)

find_package(Boost
    REQUIRED
    filesystem
)

set_property(TARGET utils PROPERTY CXX_STANDARD 14)

target_include_directories(utils
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${Boost_INCLUDE_DIRS}
)
