cmake_minimum_required (VERSION 3.5)

add_executable (Test
    main.cpp
    storage.cpp
    pow.cpp
    serialization.cpp
    signature.cpp
    rate_limiter.cpp
    command_line.cpp
)

# library under test

loki_add_subdirectory(../common common)
loki_add_subdirectory(../storage storage)
loki_add_subdirectory(../pow pow)
loki_add_subdirectory(../utils utils)
loki_add_subdirectory(../crypto crypto)
loki_add_subdirectory(../httpserver httpserver)

target_link_libraries(Test PRIVATE common storage pow utils crypto httpserver_lib)

# boost
find_package(Boost REQUIRED unit_test_framework)

target_link_libraries(Test PRIVATE Boost::unit_test_framework)
