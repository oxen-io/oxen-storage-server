
subbuilddir:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)
ifeq ($(USE_SINGLE_BUILDDIR),)
  builddir := build/$(subbuilddir)
  topdir   := ../../../..
else
  builddir := build
  topdir   := ../..
endif

all: release-httpserver

clean:
	rm -rf build

debug-all:
	mkdir -p $(builddir)/debug && cd $(builddir)/debug && cmake $(topdir) -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON && cmake --build .

debug-httpserver:
	mkdir -p $(builddir)/debug && cd $(builddir)/debug && cmake $(topdir) -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF && cmake --build .

release-all:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && cmake --build .

release-httpserver:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF && cmake --build .

ninja-debug-all:
	mkdir -p $(builddir)/debug && cd $(builddir)/debug && cmake -GNinja $(topdir) -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON && ninja

ninja-debug-httpserver:
	mkdir -p $(builddir)/debug && cd $(builddir)/debug && cmake -GNinja $(topdir) -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF && ninja

ninja-release-all:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake -GNinja $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && ninja

ninja-release-httpserver:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake -GNinja $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF && ninja

.PHONY: all clean release-all release-httpserver debug-all debug-httpserver ninja-release-all ninja-release-httpserver ninja-debug-all ninja-debug-httpserver
