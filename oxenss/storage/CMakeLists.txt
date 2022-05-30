
add_library(storage STATIC
    database.cpp
)

target_link_libraries(storage PRIVATE common logging utils SQLiteCpp)
