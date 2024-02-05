#!/usr/bin/env bash

CLANG_FORMAT_DESIRED_VERSION=15

binary=$(command -v clang-format-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
if [ $? -ne 0 ]; then
    binary=$(command -v clang-format-mp-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
fi
if [ $? -ne 0 ]; then
    binary=$(command -v clang-format 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
    version=$(clang-format --version)
    if [[ ! $version == *"clang-format version $CLANG_FORMAT_DESIRED_VERSION"* ]]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
fi

BLACK=$(command -v black 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "Please install the 'black' python3 package and make sure it is available in your path"
    exit 1
fi


black_args=()

cd "$(dirname $0)/../"
sources=$(find oxenss unit_test | grep -E '\.[hc](pp)?$' | grep -v '\#\|Catch2')
if [ "$1" = "verify" ] ; then
    if [ $($binary --output-replacements-xml $sources | grep '</replacement>' | wc -l) -ne 0 ] ; then
        exit 2
    fi
    black_args=(--check)
else
    $binary -i $sources &> /dev/null
fi

jsonnet_format=$(command -v jsonnetfmt 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$1" = "verify" ]; then
        if ! $jsonnet_format --test .drone.jsonnet; then
            exit 4
        fi
    else
        $jsonnet_format --in-place .drone.jsonnet
    fi
fi

if ! black "${black_args[@]}" network-tests/*.py; then
    exit 5
fi
