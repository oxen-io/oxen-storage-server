#!/bin/bash

bash -i

set -e
set -x

curl -L https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.bz2 | tar xj

cd boost_1_70_0

./bootstrap.sh

./b2 -a --prefix=${PWD}/../boost link=static variant=release install \
        --with-program_options \
        --with-filesystem \
        --with-system \
        --with-chrono \
        --with-thread \
        --with-log \
        --with-test


