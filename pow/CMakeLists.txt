set(SOURCES
    include/pow.hpp
    src/pow.cpp
)

add_library(pow STATIC ${SOURCES})

find_package(OpenSSL REQUIRED)
target_link_libraries(pow PUBLIC OpenSSL::SSL)

target_include_directories(pow
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

include_directories(pow ${Boost_INCLUDE_DIRS})
target_link_libraries(pow PRIVATE ${Boost_LIBRARIES})
