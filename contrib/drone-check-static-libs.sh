#!/usr/bin/env bash

# Script used with Drone CI to check that a statically build oxen only links against the expected
# base system libraries.  Expects to be run with pwd of the build directory.

set -o errexit

anybad=
for bin in oxen-storage; do
    bad=
    if [ "$DRONE_STAGE_OS" == "darwin" ]; then
        if otool -L $bin | grep -Ev '^'$bin':|^\t(/usr/lib/libSystem\.|/usr/lib/libc\+\+\.|/usr/lib/libresolv\.|/System/Library/Frameworks/(CoreFoundation|IOKit|Security|SystemConfiguration))'; then
            bad=1
        fi
    elif [ "$DRONE_STAGE_OS" == "linux" ]; then
        if ldd $bin | grep -Ev '(linux-vdso|ld-linux-x86-64|lib(pthread|dl|resolv|stdc\+\+|gcc_s|c|m))\.so'; then
            bad=1
        fi
    else
        echo -e "\n\n\n\n\e[31;1mDon't know how to check linked libs on $DRONE_STAGE_OS\e[0m\n\n\n"
        exit 1
    fi

    if [ -n "$bad" ]; then
        anybad=1
        echo -e "\n\n\n\n\e[31;1m$bin links to unexpected libraries\e[0m\n\n\n"
    fi
done

if [ -n "$anybad" ]; then
    exit 1
fi

echo -e "\n\n\n\n\e[32;1mNo unexpected linked libraries found\e[0m\n\n\n"
