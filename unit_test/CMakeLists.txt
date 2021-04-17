cmake_minimum_required (VERSION 3.5)

add_executable (Test
    command_line.cpp
    ip_utils.cpp
    main.cpp
    onion_requests.cpp
    rate_limiter.cpp
    serialization.cpp
    signature.cpp
    storage.cpp
    service_node.cpp
)

target_link_libraries(Test PRIVATE common storage utils crypto httpserver_lib)
target_include_directories(Test PRIVATE ../httpserver)

# boost
if(NOT BUILD_STATIC_DEPS)
  find_package(Boost REQUIRED unit_test_framework)
endif()

target_link_libraries(Test PRIVATE Boost::unit_test_framework)
