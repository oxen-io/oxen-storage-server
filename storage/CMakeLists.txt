cmake_minimum_required(VERSION 3.5)

add_library(storage STATIC
    src/Database.cpp
)

target_include_directories(storage
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(storage PRIVATE common utils)
if(BUILD_STATIC_DEPS)
  # sqlite3 target already set up
else()
  if (NOT SQLITE3_LIBRARIES)
    pkg_check_modules(SQLITE3 REQUIRED sqlite3)
  endif()
  find_library(sqlite3_link_libs NAMES ${SQLITE3_LIBRARIES} PATHS ${SQLITE3_LIBRARY_DIRS})
  message(STATUS "sqlite3: ${SQLITE3_LIBRARIES} ${sqlite3_link_libs}")
  add_library(sqlite3 INTERFACE)
  target_link_libraries(sqlite3 INTERFACE ${sqlite3_link_libs})
  target_include_directories(sqlite3 INTERFACE ${SQLITE3_INCLUDE_DIRS})
endif()
target_link_libraries(storage PRIVATE sqlite3)

target_link_libraries(storage PRIVATE Boost::boost)
