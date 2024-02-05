
add_subdirectory(Catch2)

add_executable(Test
    main.cpp

    encrypt.cpp
    onion_requests.cpp
    rate_limiter.cpp
    serialization.cpp
    service_node.cpp
    storage.cpp
    swarm.cpp
)

target_link_libraries(Test
    PRIVATE
    common storage utils crypto snode rpc server
    Catch2::Catch2)

target_include_directories(Test PRIVATE ..)
