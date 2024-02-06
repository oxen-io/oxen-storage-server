# Figure out if we need -lstdc++fs or -lc++fs and add it to the `filesystem` interface, if needed
# (otherwise just leave it an empty interface library; linking to it will do nothing).  The former
# is needed for gcc before v9, and the latter with libc++ before llvm v9.  But this gets more
# complicated than just using the compiler, because clang on linux by default uses libstdc++, so
# we'll just give up and see what works.

add_library(oxenss_filesystem INTERFACE)

set(filesystem_code [[
#include <filesystem>

int main() {
    auto cwd = std::filesystem::current_path();
    return !cwd.string().empty();
}
]])

if(CMAKE_CXX_COMPILER STREQUAL "AppleClang" AND CMAKE_OSX_DEPLOYMENT_TARGET)
  # It seems that check_cxx_source_compiles doesn't respect the CMAKE_OSX_DEPLOYMENT_TARGET, so this
  # check would pass on Catalina (10.15) and then later compilation would fail because you aren't
  # allowed to use <filesystem> when the deployment target is anything before 10.15.
  set(CMAKE_REQUIRED_FLAGS -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET})
endif()

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("${filesystem_code}" filesystem_compiled)
if(filesystem_compiled)
  message(STATUS "No extra link flag needed for std::filesystem")
  set(filesystem_is_good ON)
else()
  foreach(fslib stdc++fs c++fs)
    set(CMAKE_REQUIRED_LIBRARIES -l${fslib})
    check_cxx_source_compiles("${filesystem_code}" filesystem_compiled_${fslib})
    if (filesystem_compiled_${fslib})
      message(STATUS "Using -l${fslib} for std::filesystem support")
      target_link_libraries(oxenss_filesystem INTERFACE ${fslib})
      set(filesystem_is_good ON)
      break()
    endif()
  endforeach()
endif()
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT filesystem_is_good)
  # Probably broken AF macos
  message(FATAL_ERROR "std::filesystem is not available, apparently this compiler isn't C++17 compliant")
endif()
