
add_library(server STATIC
    https.cpp
    mqbase.cpp
    omq.cpp
    omq_logger.cpp
    quic.cpp
    server_certificates.cpp
    utils.cpp)

find_package(Threads)

target_link_libraries(server
    PUBLIC
    uWebSockets
    quic    # public so it gets to /daemon
    PRIVATE
    common
    utils
    rpc
    snode
    logging
    OpenSSL::SSL
    oxenmq::oxenmq
    sodium
    Threads::Threads)

set_source_files_properties(server_certificates.cpp PROPERTIES COMPILE_FLAGS -Wno-error=deprecated-declarations)
