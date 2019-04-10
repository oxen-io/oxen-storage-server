SUB_DIR:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)
ifeq ($(USE_SINGLE_BUILD_DIR),)
  BUILD_DIR := build/$(SUB_DIR)
  TOP_DIR   := ../../../..
else
  BUILD_DIR := build
  TOP_DIR   := ../..
endif

ifeq ($(DEBUG),)
	BUILD_TYPE := Release
else
	BUILD_TYPE := Debug
endif

ifeq ($(GEN),)
	CMAKE := cmake
else
	CMAKE := cmake -G$(GEN)
endif

BUILD_TESTS ?= ON

MKDIR := mkdir -p $(BUILD_DIR)/$(BUILD_TYPE) && cd $(BUILD_DIR)/$(BUILD_TYPE)

MAKE_CMD := $(CMAKE) $(TOP_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DBUILD_TESTS=$(BUILD_TESTS) && cmake --build .

all:
	$(MKDIR) && $(MAKE_CMD)

clean:
	rm -rf build

.PHONY: all clean
