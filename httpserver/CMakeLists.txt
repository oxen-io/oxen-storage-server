add_definitions(-DDISABLE_ENCRYPTION)

# Stop compiling post first error
add_definitions(-Wfatal-errors)

add_library(httpserver_lib STATIC
    main.cpp
    http_connection.cpp
    swarm.cpp
    service_node.cpp
    serialization.cpp
    rate_limiter.cpp
    https_client.cpp
    stats.cpp
    security.cpp
    command_line.cpp
    dns_text_records.cpp
    reachability_testing.cpp
    lmq_server.cpp
    request_handler.cpp
    onion_processing.cpp
    ip_utils.cpp
    )

set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
add_subdirectory(../vendors/nlohmann_json nlohmann_json)

# TODO: enable more warnings!
target_compile_options(httpserver_lib PRIVATE -Werror=return-type)

target_link_libraries(httpserver_lib PUBLIC
    common storage utils pow crypto
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    oxenmq::oxenmq
    Boost::system Boost::program_options)

# libresolv is needed on linux, but not on BSDs, so only link it if we can find it
find_library(RESOLV resolv)
if(RESOLV)
    target_link_libraries(httpserver_lib PUBLIC ${RESOLV})
endif()

set(BIN_NAME oxen-storage)

add_executable(httpserver main.cpp)
target_compile_options(httpserver PRIVATE -Wall -Wextra -Werror)
set_target_properties(httpserver PROPERTIES OUTPUT_NAME ${BIN_NAME})
target_link_libraries(httpserver PRIVATE httpserver_lib)
install(TARGETS httpserver DESTINATION bin)
# Build Info
find_package(Git)
if(GIT_FOUND)
    execute_process(
        COMMAND
            git rev-parse --short HEAD
        OUTPUT_VARIABLE
            SHORT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    set(SHORT_HASH "unknown")
endif()
string(TIMESTAMP BUILD_TIME UTC)
message(STATUS "using git commit hash ${SHORT_HASH}")
message(STATUS "using UTC build time ${BUILD_TIME}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
target_sources(httpserver_lib PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
target_include_directories(httpserver_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

if(NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SYSTEMD libsystemd)
        # Default ENABLE_SYSTEMD to true if we found it
        option(ENABLE_SYSTEMD "enable systemd integration for sd_notify" ${SYSTEMD_FOUND})

        if(ENABLE_SYSTEMD)
            if(NOT SYSTEMD_FOUND)
                message(FATAL_ERROR "libsystemd not found")
            endif()
            target_compile_definitions(httpserver PRIVATE ENABLE_SYSTEMD)
            target_include_directories(httpserver PRIVATE ${SYSTEMD_INCLUDE_DIRS})
            target_link_libraries(httpserver PRIVATE ${SYSTEMD_LIBRARIES})
        endif()
    endif()
endif()


#
