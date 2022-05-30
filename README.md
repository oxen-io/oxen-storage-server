# Oxen Storage Server

Storage server for Oxen Service Nodes

## Binary releases

Pre-built releases (with system service files) are available for Ubuntu/Debian on
https://deb.oxen.io and are recommended for simple deployment and updates on those distributions.

## Building from source

The default build compiles for the current system and requires the following be installed (including
headers/dev packages for the libraries):

Requirements:
* cmake >= 3.10
* OpenSSL >= 1.1.1
* libsodium >= 1.0.17
* pkg-config (any version)
* libcurl
* jemalloc (not strictly required but recommended for reduced long-term memory use)
* autoconf (for building jemalloc)

Other dependencies will be used from the system if found, but if not found will be compiled and
built statically from bundled versions:
* spdlog >= 1.8
* libzmq >= 4.3
* oxen-mq >= 1.2.6
* oxen-encoding >= 1.0.1
* sqlite >= 3.35.5

You can, however, instruct the build to download and build static versions of all of these
dependencies (other than autoconf) as part of the build by adding the `-DBUILD_STATIC_DEPS=ON`
option to the `cmake` command below.  (This will, however, result in a slower build and larger,
slower binary, as is typical for static builds).

```
git submodule update --init --recursive
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j4
```

The build will produce a `./build/httpserver/oxen-storage` binary.  You can run it with `--help` to
see supported run-time options.

# Running

Oxen Storage Server is a required component of an Oxen Service Node and needs to talk to a running
`oxend` in order to join the network.  The program defaults are designed to work with a default
oxend, but for advanced configurations (e.g. to run on different ports) you may need to use other
options.  Run the program with `--help` to see all available options.

See https://docs.oxen.io/ for additional details on setting up and running an Oxen Service Node.
