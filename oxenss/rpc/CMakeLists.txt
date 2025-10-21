
add_library(rpc STATIC
    client_rpc_endpoints.cpp
    onion_processing.cpp
    oxend_rpc.cpp
    rate_limiter.cpp
    request_handler.cpp)

target_link_libraries(rpc
    PUBLIC
    nlohmann_json::nlohmann_json
    PRIVATE
    crypto
    server
    snode
    http
    utils
    logging
    version

    cpr::cpr
    oxenmq::oxenmq
    oxenc::oxenc
    sodium)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(rpc PUBLIC JSON_DIAGNOSTICS=1)
endif()
