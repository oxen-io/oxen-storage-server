cmake_minimum_required (VERSION 3.1)

add_executable (Test
    main.cpp
    storage.cpp
    pow.cpp
    serialization.cpp
    signature.cpp
    rate_limiter.cpp
    # TODO: remove once httpserver provides a static lib to link against
    ../httpserver/serialization.cpp
    ../httpserver/rate_limiter.cpp
)

# library under test

loki_add_subdirectory(../storage storage)
loki_add_subdirectory(../pow pow)
loki_add_subdirectory(../utils utils)
loki_add_subdirectory(../crypto crypto)

target_link_libraries(Test PRIVATE storage pow utils crypto)
target_include_directories(Test PRIVATE ../httpserver)

# boost
find_package(Boost
REQUIRED
system
filesystem
chrono
thread
unit_test_framework
log
)

set_property(TARGET Test PROPERTY CXX_STANDARD 14)

target_include_directories(Test PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(Test PRIVATE ${Boost_LIBRARIES})
