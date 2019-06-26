if (TARGET utils)
    return()
endif()

set(SOURCES
    include/utils.hpp
    src/utils.cpp
)

add_library(utils STATIC ${SOURCES})

set_property(TARGET utils PROPERTY CXX_STANDARD 14)

target_include_directories(utils
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)
