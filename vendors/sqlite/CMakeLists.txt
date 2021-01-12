cmake_minimum_required(VERSION 3.1)

# Clear polluted flags. For example, -Ofast would not work with sqlite
unset(CMAKE_C_FLAGS)
unset(CMAKE_C_FLAGS_RELEASE)
unset(CMAKE_C_FLAGS_DEBUG)
unset(CMAKE_CXX_FLAGS)
unset(CMAKE_CXX_FLAGS_RELEASE)
unset(CMAKE_CXX_FLAGS_DEBUG)


set(CMAKE_C_FLAGS "-Wformat -Wformat-security -fstack-protector -fstack-protector-strong -O2")
set(CMAKE_CXX_FLAGS "-Wformat -Wformat-security -fstack-protector -fstack-protector-strong -O2")
set(CMAKE_EXE_LINKER_FLAGS "-pie")

project(sqlite)

find_package(Threads)

add_library(sqlite STATIC sqlite3.c)

target_include_directories(sqlite PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

# https://www.sqlite.org/compile.html#recommended_compile_time_options
target_compile_definitions(sqlite PRIVATE
    SQLITE_DEFAULT_MEMSTATUS=0 # no need for runtime performance tracking
    SQLITE_LIKE_DOESNT_MATCH_BLOBS # no need to match blobs
    SQLITE_MAX_EXPR_DEPTH=0 # unlimited expression tree depth
    SQLITE_OMIT_DECLTYPE # no need to query the column's types
    SQLITE_OMIT_DEPRECATED # no need for deprecated stuff
    SQLITE_OMIT_PROGRESS_CALLBACK # no need for progress callback
)

target_link_libraries(sqlite PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
set_property(TARGET sqlite PROPERTY POSITION_INDEPENDENT_CODE ON)
