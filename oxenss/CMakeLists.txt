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
if(OXENSS_VERSIONTAG)
    set(VERSIONTAG "${OXENSS_VERSIONTAG}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
else()
    set(GIT_INDEX_FILE "${PROJECT_SOURCE_DIR}/.git/index")
    find_package(Git)
    if(EXISTS ${GIT_INDEX_FILE} AND ( GIT_FOUND OR Git_FOUND) )
        message(STATUS "Found Git: ${GIT_EXECUTABLE}")

        set(genversion_args "-DGIT=${GIT_EXECUTABLE}")
        foreach(v oxenss_VERSION oxenss_VERSION_MAJOR oxenss_VERSION_MINOR oxenss_VERSION_PATCH)
            list(APPEND genversion_args "-D${v}=${${v}}")
        endforeach()

        add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
            COMMAND
                "${CMAKE_COMMAND}"
                ${genversion_args}
                "-DSRC=${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in"
                "-DDEST=${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
                "-P" "${PROJECT_SOURCE_DIR}/cmake/GenVersion.cmake"
            DEPENDS
                "${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in"
                "${GIT_INDEX_FILE}")
    else()
        message(STATUS "Git was not found! Setting version to to nogit")
        set(VERSIONTAG "nogit")
        configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
    endif()
endif()

add_library(version STATIC "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
