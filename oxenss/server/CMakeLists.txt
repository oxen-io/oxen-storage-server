
add_library(server STATIC
    https.cpp
    omq.cpp
    omq_logger.cpp
    omq_monitor.cpp
    server_certificates.cpp)

find_package(Threads)

target_link_libraries(server
    PUBLIC
    uWebSockets
    PRIVATE
    common
    utils
    rpc
    logging
    OpenSSL::SSL
    oxenmq::oxenmq
    sodium
    Threads::Threads)

set_source_files_properties(server_certificates.cpp PROPERTIES COMPILE_FLAGS -Wno-error=deprecated-declarations)
