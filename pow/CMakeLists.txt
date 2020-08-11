add_library(pow STATIC
    src/pow.cpp
)


loki_add_subdirectory(../utils utils)

set_property(TARGET pow PROPERTY CXX_STANDARD 17)
set_property(TARGET pow PROPERTY CXX_STANDARD_REQUIRED TRUE)

find_package(OpenSSL REQUIRED)
target_link_libraries(pow PRIVATE OpenSSL::SSL)

target_include_directories(pow
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
    )
endif()

target_include_directories(pow PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(pow PRIVATE ${Boost_LIBRARIES})
target_link_libraries(pow PRIVATE utils)
