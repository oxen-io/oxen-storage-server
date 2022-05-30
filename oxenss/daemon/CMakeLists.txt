
add_executable(daemon
    command_line.cpp
    oxen-storage.cpp)

target_link_libraries(daemon
    PRIVATE
    common crypto logging rpc server snode storage utils version
    CLI11::CLI11)

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
            target_compile_definitions(daemon PRIVATE ENABLE_SYSTEMD)
            target_include_directories(daemon PRIVATE ${SYSTEMD_INCLUDE_DIRS})
            target_link_libraries(daemon PRIVATE ${SYSTEMD_LIBRARIES})
        endif()
    endif()
endif()

set(BIN_NAME oxen-storage)

set_target_properties(daemon PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
    OUTPUT_NAME oxen-storage)
install(TARGETS daemon DESTINATION bin)
