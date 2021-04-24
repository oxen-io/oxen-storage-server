# Set up a `make strip` target that strips the built binary.
add_custom_target(strip COMMAND ${CMAKE_STRIP} $<TARGET_FILE:httpserver>)

# Figure out an appropriate tag using git to figure out a good filename
find_package(Git)
set(git_tag "-unknown")
if(GIT_FOUND)
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE curr_commit OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse stable RESULT_VARIABLE ret2 OUTPUT_VARIABLE stable_commit OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT ret AND curr_commit STREQUAL "${stable_commit}")
    # Get the tag description; for a tagged release this will be just the tag (v1.2.3); for
    # something following a tag this will be something like "v1.2.3-2-abcdef" for something 2
    # commits beyond the tag, currently at commit "abcdef".
    execute_process(COMMAND "${GIT_EXECUTABLE}" describe --tags --abbrev=6 HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE tag OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ret AND tag MATCHES "v[0-9]+\\.[0-9]+\\.[0-9]+(-.*)")
      # We're building something following a tagged release, so append the post-version git tag info
      set(git_tag "${CMAKE_MATCH_1}")
    else()
      set(git_tag "") # No tag appended if we're building a tagged stable branch release
    endif()
  else()
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=9 HEAD RESULT_VARIABLE ret OUTPUT_VARIABLE commithash OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ret)
      set(git_tag "-${commithash}")
    endif()
  endif()
endif()

set(tar_os ${CMAKE_SYSTEM_NAME})
set(default_archive create_tarxz)
if(tar_os STREQUAL "Linux")
  set(tar_os "linux-${CMAKE_SYSTEM_PROCESSOR}")
elseif(tar_os STREQUAL "Darwin")
  set(tar_os "macos")
elseif(tar_os STREQUAL "Windows")
  if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES i686-.*mingw)
    set(tar_os "win-x86")
  elseif(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES x86_64-.*mingw)
    set(tar_os "win-x64")
  else()
    set(tar_os "windows") # Don't know what arch
  endif()
  set(default_archive create_zip) # .tar.xz files are too scary for Windows users
endif()
set(tar_dir "oxen-storage-${tar_os}-${PROJECT_VERSION}${git_tag}")
add_custom_target(create_tarxz
  COMMAND ${CMAKE_COMMAND} -E make_directory "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:httpserver> "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E tar cvJ "${tar_dir}.tar.xz" -- "${tar_dir}"
  DEPENDS httpserver)

add_custom_target(create_zip
  COMMAND ${CMAKE_COMMAND} -E make_directory "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:httpserver> "${tar_dir}"
  COMMAND ${CMAKE_COMMAND} -E tar cv "${tar_dir}.zip" --format=zip -- "${tar_dir}"
  DEPENDS httpserver)

add_custom_target(create_archive DEPENDS ${default_archive})

