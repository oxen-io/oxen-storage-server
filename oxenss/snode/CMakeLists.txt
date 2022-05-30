
add_library(snode STATIC
    reachability_testing.cpp
    serialization.cpp
    service_node.cpp
    stats.cpp
    swarm.cpp)

target_link_libraries(snode
    PUBLIC
    oxenmq::oxenmq
    PRIVATE
    crypto
    utils
    server
    logging
    rpc
    oxenc::oxenc

    cpr::cpr
    sodium)
