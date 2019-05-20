SUB_DIR:=$(shell echo  `uname | sed -e 's|[:/\\ \(\)]|_|g'`/`git branch | grep '\* ' | cut -f2- -d' '| sed -e 's|[:/\\ \(\)]|_|g'`)

ifeq ($(DEBUG),)
	BUILD_TYPE := Release
else
	BUILD_TYPE := Debug
endif

ifeq ($(USE_SINGLE_BUILD_DIR),)
  BUILD_DIR := build/$(SUB_DIR)/$(BUILD_TYPE)
  TOP_DIR   := ../../../..
else
  BUILD_DIR := build
  TOP_DIR   := ..
endif

ifeq ($(GEN),)
	CMAKE := cmake
else
	CMAKE := cmake -G$(GEN)
endif

BUILD_TESTS ?= ON

BUILD_STATIC ?= ON

MKDIR := mkdir -p $(BUILD_DIR) && cd $(BUILD_DIR)

all:
	$(MKDIR) && \
	$(CMAKE) $(TOP_DIR) \
		-DBoost_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DBUILD_TESTS=$(BUILD_TESTS) \
		&& cmake --build .

integration-test:
	$(MKDIR) && \
	$(CMAKE) $(TOP_DIR) \
		-DBoost_USE_STATIC_LIBS=$(BUILD_STATIC) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DBUILD_TESTS=$(BUILD_TESTS) \
		-DINTEGRATION_TEST=ON \
		&& cmake --build .

tests: all
	./$(BUILD_DIR)/unit_test/Test --log_level=all

clean:
	rm -rf build/$(SUB_DIR)

clean-all:
	rm -rf build

format:
	clang-format -style=file -i \
		pow/**/*.{cpp,hpp} \
		crypto/**/*.{cpp,hpp} \
		storage/**/*.{cpp,hpp} \
		utils/**/*.{cpp,hpp} \
		httpserver/*.{cpp,h} \
		unit_test/*.cpp


.PHONY: all clean format
