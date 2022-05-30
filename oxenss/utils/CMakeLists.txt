
add_library(utils STATIC
    file.cpp
    random.cpp
    string_utils.cpp
)

target_link_libraries(utils PRIVATE spdlog::spdlog)
