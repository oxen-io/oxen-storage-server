cmake_minimum_required (VERSION 3.1)

add_executable (Test main.cpp storage.cpp pow.cpp)

set_property(TARGET Test PROPERTY CXX_STANDARD 11)

# library under test

loki_add_subdirectory(../storage storage)
loki_add_subdirectory(../pow pow)
loki_add_subdirectory(../utils utils)
target_link_libraries(Test PRIVATE storage pow utils)

# boost
find_package(Boost
REQUIRED
system
filesystem
chrono
thread
unit_test_framework
)
# add_definitions (-DBOOST_TEST_DYN_LINK)
target_include_directories(Test PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(Test PRIVATE ${Boost_LIBRARIES})
