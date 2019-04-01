cmake_minimum_required(VERSION 2.8.0)
set(EXE loki-storage-server)
project(${EXE})

add_executable(${EXE} main.cpp http_connection.hpp)
set(Boost_USE_STATIC_LIBS   ON)
add_subdirectory(../storage storage)
add_subdirectory(../pow pow)
add_subdirectory(../crypto crypto)


find_package(OpenSSL REQUIRED)

target_link_libraries(${EXE} PRIVATE OpenSSL::SSL)
target_link_libraries(${EXE} PRIVATE sn_storage)
target_link_libraries(${EXE} PRIVATE pow)
target_link_libraries(${EXE} PRIVATE crypto)

set_property(TARGET ${EXE} PROPERTY CXX_STANDARD 11)

if(NOT Boost_FOUND)
    find_package(Boost
        REQUIRED
        system
        filesystem
        program_options
        log
    )
endif()

target_include_directories(${EXE} PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(${EXE} PRIVATE ${Boost_LIBRARIES})
