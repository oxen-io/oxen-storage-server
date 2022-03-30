
add_subdirectory(Catch2)

add_executable(Test
    main.cpp

    encrypt.cpp
    onion_requests.cpp
    rate_limiter.cpp
    serialization.cpp
    service_node.cpp
    signature.cpp
    storage.cpp
)

target_link_libraries(Test
    PRIVATE
    common storage utils crypto httpserver_lib
    Catch2::Catch2)
