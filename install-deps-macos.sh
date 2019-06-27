#!/bin/bash
set -ex
mkdir -p deps && cd deps
# openssl
openssl_install=$PWD/openssl
if [ ! -d $openssl_install ]; then
    curl https://www.openssl.org/source/openssl-1.1.1a.tar.gz > openssl-1.1.1a.tar.gz
    tar -xf openssl-1.1.1a.tar.gz
    mkdir -p $openssl_install
    pushd openssl-1.1.1a
    ./config --prefix=$openssl_install no-shared && \
        make --quiet && \
        make --quiet install
    popd
fi
# libsodium
sodium_install=$PWD/sodium
if [ ! -f $sodium_install/include/sodium.h ]; then
    curl https://download.libsodium.org/libsodium/releases/libsodium-1.0.17.tar.gz > libsodium-1.0.17.tar.gz
    tar -xf libsodium-1.0.17.tar.gz
    mkdir -p $sodium_install
    pushd libsodium-1.0.17
    ./configure --quiet --prefix=$sodium_install --enable-static --disable-shared && \
        make --quiet && \
        make --quiet install
    popd
fi

boost_install=$PWD/boost
if [ ! -f $boost_install/lib/libboost_system.a ]; then
    curl -L https://dl.bintray.com/boostorg/release/1.67.0/source/boost_1_67_0.tar.gz > boost_1_67_0.tar.gz
    tar -xf boost_1_67_0.tar.gz
    mkdir -p $boost_install
    pushd boost_1_67_0
    ./bootstrap.sh && \
        ./b2 -a -d0 --prefix=$boost_install link=static variant=release install \
        --with-program_options \
        --with-filesystem \
        --with-system \
        --with-chrono \
        --with-thread \
        --with-log \
        --with-test
    popd
fi
