# cmake bits to do a full static build, downloading and building all dependencies.

# Most of these are CACHE STRINGs so that you can override them using -DWHATEVER during cmake
# invocation to override.

set(LOCAL_MIRROR "" CACHE STRING "local mirror path/URL for lib downloads")

set(OPENSSL_VERSION 1.1.1k CACHE STRING "openssl version")
set(OPENSSL_MIRROR ${LOCAL_MIRROR} https://www.openssl.org/source CACHE STRING "openssl download mirror(s)")
set(OPENSSL_SOURCE openssl-${OPENSSL_VERSION}.tar.gz)
set(OPENSSL_HASH SHA256=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5
    CACHE STRING "openssl source hash")

set(BOOST_VERSION 1.76.0 CACHE STRING "boost version")
set(BOOST_MIRROR ${LOCAL_MIRROR} https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION}/source
    CACHE STRING "boost download mirror(s)")
string(REPLACE "." "_" BOOST_VERSION_ ${BOOST_VERSION})
set(BOOST_SOURCE boost_${BOOST_VERSION_}.tar.bz2)
set(BOOST_HASH SHA256=f0397ba6e982c4450f27bf32a2a83292aba035b827a5623a14636ea583318c41
    CACHE STRING "boost source hash")

set(SODIUM_VERSION 1.0.18 CACHE STRING "libsodium version")
set(SODIUM_MIRROR ${LOCAL_MIRROR}
  https://download.libsodium.org/libsodium/releases
  https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VERSION}-RELEASE
  CACHE STRING "libsodium mirror(s)")
set(SODIUM_SOURCE libsodium-${SODIUM_VERSION}.tar.gz)
set(SODIUM_HASH SHA512=17e8638e46d8f6f7d024fe5559eccf2b8baf23e143fadd472a7d29d228b186d86686a5e6920385fe2020729119a5f12f989c3a782afbd05a8db4819bb18666ef
  CACHE STRING "libsodium source hash")

include(sqlite3_source)

set(ZMQ_VERSION 4.3.4 CACHE STRING "libzmq version")
set(ZMQ_MIRROR ${LOCAL_MIRROR} https://github.com/zeromq/libzmq/releases/download/v${ZMQ_VERSION}
    CACHE STRING "libzmq mirror(s)")
set(ZMQ_SOURCE zeromq-${ZMQ_VERSION}.tar.gz)
set(ZMQ_HASH SHA512=e198ef9f82d392754caadd547537666d4fba0afd7d027749b3adae450516bcf284d241d4616cad3cb4ad9af8c10373d456de92dc6d115b037941659f141e7c0e
    CACHE STRING "libzmq source hash")

set(LIBUV_VERSION 1.41.0 CACHE STRING "libuv version")
set(LIBUV_MIRROR ${LOCAL_MIRROR} https://dist.libuv.org/dist/v${LIBUV_VERSION}
    CACHE STRING "libuv mirror(s)")
set(LIBUV_SOURCE libuv-v${LIBUV_VERSION}.tar.gz)
set(LIBUV_HASH SHA512=33613fa28e8136507300eba374351774849b6b39aab4e53c997a918d3bc1d1094c6123e0e509535095b14dc5daa885eadb1a67bed46622ad3cc79d62dc817e84
    CACHE STRING "libuv source hash")

set(ZLIB_VERSION 1.2.11 CACHE STRING "zlib version")
set(ZLIB_MIRROR ${LOCAL_MIRROR} https://zlib.net
    CACHE STRING "zlib mirror(s)")
set(ZLIB_SOURCE zlib-${ZLIB_VERSION}.tar.gz)
set(ZLIB_HASH SHA512=73fd3fff4adeccd4894084c15ddac89890cd10ef105dd5e1835e1e9bbb6a49ff229713bd197d203edfa17c2727700fce65a2a235f07568212d820dca88b528ae
    CACHE STRING "zlib source hash")

set(CURL_VERSION 7.76.1 CACHE STRING "curl version")
set(CURL_MIRROR ${LOCAL_MIRROR} https://curl.haxx.se/download https://curl.askapache.com
    CACHE STRING "curl mirror(s)")
set(CURL_SOURCE curl-${CURL_VERSION}.tar.xz)
set(CURL_HASH SHA256=64bb5288c39f0840c07d077e30d9052e1cbb9fa6c2dc52523824cc859e679145
    CACHE STRING "curl source hash")



include(ExternalProject)

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

file(MAKE_DIRECTORY ${DEPS_DESTDIR}/include)

set(deps_cc "${CMAKE_C_COMPILER}")
set(deps_cxx "${CMAKE_CXX_COMPILER}")

if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
if(CMAKE_CXX_COMPILER_LAUNCHER)
  set(deps_cxx "${CMAKE_CXX_COMPILER_LAUNCHER} ${deps_cxx}")
endif()

function(expand_urls output source_file)
  set(expanded)
  foreach(mirror ${ARGN})
    list(APPEND expanded "${mirror}/${source_file}")
  endforeach()
  set(${output} "${expanded}" PARENT_SCOPE)
endfunction()

function(add_static_target target ext_target libname)
  add_library(${target} STATIC IMPORTED GLOBAL)
  add_dependencies(${target} ${ext_target})
  set_target_properties(${target} PROPERTIES
    IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
  )
endfunction()



if(USE_LTO)
  set(flto "-flto")
else()
  set(flto "")
endif()

set(cross_host "")
set(cross_extra "")
if(CMAKE_CROSSCOMPILING)
  if(APPLE)
    set(cross_host "--host=${APPLE_TARGET_TRIPLE}")
  else()
    set(cross_host "--host=${ARCH_TRIPLET}")
    if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
      set(cross_extra "WINDRES=${CMAKE_RC_COMPILER}")
    endif()
  endif()
endif()



set(deps_CFLAGS "-O2 ${flto}")
set(deps_CXXFLAGS "-O2 ${flto}")
set(deps_noarch_CFLAGS "${deps_CFLAGS}")
set(deps_noarch_CXXFLAGS "${deps_CXXFLAGS}")

if(APPLE)
  foreach(lang C CXX)
    string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT}")
    if (CMAKE_OSX_DEPLOYMENT_TARGET)
        string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")
    endif()

    set(deps_noarch_${lang}FLAGS "${deps_${lang}FLAGS}")

    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
      string(APPEND deps_${lang}FLAGS " -arch ${arch}")
    endforeach()
  endforeach()
endif()

# Builds a target; takes the target name (e.g. "readline") and builds it in an external project with
# target name suffixed with `_external`.  Its upper-case value is used to get the download details
# (from the variables set above).  The following options are supported and passed through to
# ExternalProject_Add if specified.  If omitted, these defaults are used:
set(build_def_DEPENDS "")
set(build_def_PATCH_COMMAND "")
set(build_def_CONFIGURE_COMMAND ./configure ${cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
    "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}" ${cross_extra})
set(build_def_BUILD_COMMAND make)
set(build_def_INSTALL_COMMAND make install)
set(build_def_BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/lib___TARGET___.a ${DEPS_DESTDIR}/include/___TARGET___.h)
set(build_dep_TARGET_SUFFIX "")

function(build_external target)
  set(options TARGET_SUFFIX DEPENDS PATCH_COMMAND CONFIGURE_COMMAND BUILD_COMMAND INSTALL_COMMAND BUILD_BYPRODUCTS)
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "${options}")
  foreach(o ${options})
    if(NOT DEFINED arg_${o})
      set(arg_${o} ${build_def_${o}})
    endif()
  endforeach()
  string(REPLACE ___TARGET___ ${target} arg_BUILD_BYPRODUCTS "${arg_BUILD_BYPRODUCTS}")

  string(TOUPPER "${target}" prefix)
  expand_urls(urls ${${prefix}_SOURCE} ${${prefix}_MIRROR})
  ExternalProject_Add("${target}${arg_TARGET_SUFFIX}_external"
    DEPENDS ${arg_DEPENDS}
    BUILD_IN_SOURCE ON
    PREFIX ${DEPS_SOURCEDIR}
    URL ${urls}
    URL_HASH ${${prefix}_HASH}
    DOWNLOAD_NO_PROGRESS ON
    PATCH_COMMAND ${arg_PATCH_COMMAND}
    CONFIGURE_COMMAND ${arg_CONFIGURE_COMMAND}
    BUILD_COMMAND ${arg_BUILD_COMMAND}
    INSTALL_COMMAND ${arg_INSTALL_COMMAND}
    BUILD_BYPRODUCTS ${arg_BUILD_BYPRODUCTS}
  )
endfunction()

if (WIN32 OR (APPLE AND NOT IOS))
  build_external(libuv
    CONFIGURE_COMMAND ./autogen.sh && ./configure ${cross_host} ${cross_rc} --prefix=${DEPS_DESTDIR} --with-pic --disable-shared --enable-static "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}"
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libuv.a
      ${DEPS_DESTDIR}/include/uv.h
    )
  add_static_target(libuv libuv_external libuv.a)
  target_link_libraries(libuv INTERFACE ${CMAKE_DL_LIBS})
endif()



build_external(zlib
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS} -fPIC" ${cross_extra} ./configure --prefix=${DEPS_DESTDIR} --static
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libz.a
    ${DEPS_DESTDIR}/include/zlib.h
)
add_static_target(zlib zlib_external libz.a)


set(openssl_configure ./config)
set(openssl_system_env "")
set(openssl_cc "${deps_cc}")
if(CMAKE_CROSSCOMPILING)
  if(ARCH_TRIPLET STREQUAL x86_64-w64-mingw32)
    set(openssl_system_env SYSTEM=MINGW64 RC=${CMAKE_RC_COMPILER})
  elseif(ARCH_TRIPLET STREQUAL i686-w64-mingw32)
    set(openssl_system_env SYSTEM=MINGW64 RC=${CMAKE_RC_COMPILER})
  endif()
endif()
build_external(openssl
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CC=${openssl_cc} ${openssl_system_env} ${openssl_configure}
    --prefix=${DEPS_DESTDIR} ${openssl_extra_opts} no-shared no-capieng no-dso no-dtls1 no-ec_nistp_64_gcc_128 no-gost
    no-heartbeats no-md2 no-rc5 no-rdrand no-rfc3779 no-sctp no-ssl-trace no-ssl2 no-ssl3
    no-static-engine no-tests no-weak-ssl-ciphers no-zlib no-zlib-dynamic "CFLAGS=${deps_CFLAGS}"
  INSTALL_COMMAND make install_sw
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libssl.a ${DEPS_DESTDIR}/lib/libcrypto.a
    ${DEPS_DESTDIR}/include/openssl/ssl.h ${DEPS_DESTDIR}/include/openssl/crypto.h
)
add_static_target(OpenSSL::SSL openssl_external libssl.a)
add_static_target(OpenSSL::Crypto openssl_external libcrypto.a)
set(OPENSSL_INCLUDE_DIR ${DEPS_DESTDIR}/include)
set(OPENSSL_VERSION 1.1.1)



set(boost_threadapi "pthread")
set(boost_bootstrap_cxx "--cxx=${deps_cxx}")
set(boost_toolset "")
set(boost_extra "")
if(USE_LTO)
  list(APPEND boost_extra "lto=on")
endif()
if(CMAKE_CROSSCOMPILING)
  set(boost_bootstrap_cxx "") # need to use our native compiler to bootstrap
  if(ARCH_TRIPLET MATCHES mingw)
    set(boost_threadapi win32)
    list(APPEND boost_extra "target-os=windows")
    if(ARCH_TRIPLET MATCHES x86_64)
      list(APPEND boost_extra "address-model=64")
    else()
      list(APPEND boost_extra "address-model=32")
    endif()
  endif()
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
  set(boost_toolset gcc)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
  set(boost_toolset clang)
else()
  message(FATAL_ERROR "don't know how to build boost with ${CMAKE_CXX_COMPILER_ID}")
endif()

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam "using ${boost_toolset} : : ${deps_cxx} ;")

set(boost_buildflags "cxxflags=-fPIC")
if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
  string(APPEND boost_buildflags " -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}" "cflags=-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

set(boost_libs program_options)
set(boost_with_libs_extra)
string(REPLACE ";" "," boost_with_libraries "${boost_libs}")
set(boost_static_libraries)
foreach(lib ${boost_libs})
    list(APPEND boost_static_libraries "${DEPS_DESTDIR}/lib/libboost_${lib}.a")
endforeach()

build_external(boost
  #  PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam tools/build/src/user-config.jam
  CONFIGURE_COMMAND
    ./tools/build/src/engine/build.sh ${boost_toolset} ${boost_bootstrap_cxx}
  BUILD_COMMAND
    cp tools/build/src/engine/b2 .
  INSTALL_COMMAND
    ./b2 -d0 variant=release link=static runtime-link=static optimization=speed ${boost_extra}
      threading=multi threadapi=${boost_threadapi} ${boost_buildflags} cxxstd=17 visibility=global
      --disable-icu --user-config=${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam
      --prefix=${DEPS_DESTDIR} --exec-prefix=${DEPS_DESTDIR} --libdir=${DEPS_DESTDIR}/lib --includedir=${DEPS_DESTDIR}/include
      --with-program_options --with-system ${boost_with_libs_extra}
      install
  BUILD_BYPRODUCTS
    ${boost_static_libraries}
    ${DEPS_DESTDIR}/include/boost/version.hpp
)
add_library(boost_core INTERFACE)
add_dependencies(boost_core INTERFACE boost_external)
target_include_directories(boost_core SYSTEM INTERFACE ${DEPS_DESTDIR}/include)
add_library(Boost::boost ALIAS boost_core)
foreach(boostlib ${boost_libs})
  add_static_target(Boost::${boostlib} boost_external libboost_${boostlib}.a)
  target_link_libraries(Boost::${boostlib} INTERFACE boost_core)
endforeach()
set(Boost_FOUND ON)
set(Boost_VERSION ${BOOST_VERSION})



build_external(sqlite3
  BUILD_COMMAND true
  INSTALL_COMMAND make install-includeHEADERS install-libLTLIBRARIES)
add_static_target(SQLite::SQLite3 sqlite3_external libsqlite3.a)



build_external(sodium)
add_static_target(sodium sodium_external libsodium.a)


if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  set(zmq_patch PATCH_COMMAND patch -p1 -i ${PROJECT_SOURCE_DIR}/utils/build_scripts/libzmq-mingw-closesocket.patch)
endif()

set(zmq_cross_host "${cross_host}")

build_external(zmq
  DEPENDS sodium_external
  ${zmq_patch}
  CONFIGURE_COMMAND ./configure ${zmq_cross_host} --prefix=${DEPS_DESTDIR} --enable-static --disable-shared
    --disable-curve-keygen --enable-curve --disable-drafts --disable-libunwind --with-libsodium
    --without-pgm --without-norm --without-vmci --without-docs --with-pic --disable-Werror
    "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=-fstack-protector ${deps_CFLAGS}" "CXXFLAGS=-fstack-protector ${deps_CXXFLAGS}"
    ${cross_extra}
    "sodium_CFLAGS=-I${DEPS_DESTDIR}/include" "sodium_LIBS=-L${DEPS_DESTDIR}/lib -lsodium"
)
add_static_target(libzmq zmq_external libzmq.a)

set(libzmq_link_libs "sodium")
if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  list(APPEND libzmq_link_libs iphlpapi)
endif()

set_target_properties(libzmq PROPERTIES
    INTERFACE_LINK_LIBRARIES "${libzmq_link_libs}"
    INTERFACE_COMPILE_DEFINITIONS "ZMQ_STATIC")


set(curl_extra)
if(WIN32)
  set(curl_ssl_opts --without-ssl --with-schannel)
elseif(APPLE)
  set(curl_ssl_opts --without-ssl --with-secure-transport)
else()
  set(curl_ssl_opts --with-ssl=${DEPS_DESTDIR})
  set(curl_extra "LIBS=-pthread")
endif()

build_external(curl
  DEPENDS openssl_external zlib_external
  CONFIGURE_COMMAND ./configure ${cross_host} ${cross_extra} --prefix=${DEPS_DESTDIR} --disable-shared
  --enable-static --disable-ares --disable-ftp --disable-ldap --disable-laps --disable-rtsp
  --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb
  --disable-smtp --disable-gopher --disable-manual --disable-libcurl-option --enable-http
  --enable-ipv6 --disable-threaded-resolver --disable-pthreads --disable-verbose --disable-sspi
  --enable-crypto-auth --disable-ntlm-wb --disable-tls-srp --disable-unix-sockets --disable-cookies
  --enable-http-auth --enable-doh --disable-mime --enable-dateparse --disable-netrc --without-libidn2
  --disable-progress-meter --without-brotli --with-zlib=${DEPS_DESTDIR} ${curl_ssl_opts}
  --without-libmetalink --without-librtmp --disable-versioned-symbols --enable-hidden-symbols
  --without-zsh-functions-dir --without-fish-functions-dir
  "CC=${deps_cc}" "CFLAGS=${deps_noarch_CFLAGS}${cflags_extra}" ${curl_extra}
  BUILD_COMMAND true
  INSTALL_COMMAND make -C lib install && make -C include install
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libcurl.a
    ${DEPS_DESTDIR}/include/curl/curl.h
)

add_static_target(CURL::libcurl curl_external libcurl.a)
set(libcurl_link_libs zlib)
if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  list(APPEND libcurl_link_libs crypt32)
elseif(APPLE)
  list(APPEND libcurl_link_libs "-framework Security -framework CoreFoundation")
endif()
set_target_properties(CURL::libcurl PROPERTIES
  INTERFACE_LINK_LIBRARIES "${libcurl_link_libs}"
  INTERFACE_COMPILE_DEFINITIONS "CURL_STATICLIB")
