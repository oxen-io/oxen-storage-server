
subbuilddir:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)
ifeq ($(USE_SINGLE_BUILDDIR),)
  builddir := build/"$(subbuilddir)"
  topdir   := ../../../..
else
  builddir := build
  topdir   := ../..
endif

all: release-httpserver

clean:
	rm -rf build

release-all:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && cmake --build .

release-httpserver:
	mkdir -p $(builddir)/release && cd $(builddir)/release && cmake $(topdir) -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF && cmake --build .

.PHONY: all clean release-all release-httpserver
