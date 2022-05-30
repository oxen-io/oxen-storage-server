include_directories(..)

add_compile_options(-Wall)

option(WARNINGS_AS_ERRORS "Treat all compiler warnings as errors." OFF)
option(EXTRA_WARNINGS "Enable extra compiler warnings." OFF)

if(EXTRA_WARNINGS)
  add_compile_options(-Wextra)
endif()
if(WARNINGS_AS_ERRORS)
  add_compile_options(-Werror)
endif()

add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(daemon)
add_subdirectory(logging)
add_subdirectory(rpc)
add_subdirectory(server)
add_subdirectory(snode)
add_subdirectory(storage)
add_subdirectory(utils)


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
add_library(version STATIC "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
