CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -Iinclude

# Optional extension for output binaries (set to .exe when cross-compiling for Windows)
OUT_EXT ?=
# Cross-compile prefix (override when calling make): e.g. `make windows CROSS_PREFIX=i686-w64-mingw32-`
CROSS_PREFIX ?= x86_64-w64-mingw32-

# Optional sanitizer build (use `make SANITIZE=1` to enable AddressSanitizer/UBSAN)
ifdef SANITIZE
CXXFLAGS := $(CXXFLAGS) -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
endif

SRC_DIR := src
OBJ_DIR := build
BIN_DIR := bin

# Explicit targets: only build the `api` and `generator` programs by default.
# This avoids building the legacy `simulator` binary which we no longer ship.
TARGETS := api generator
MAIN_BINS := $(patsubst %,$(BIN_DIR)/%$(OUT_EXT),$(TARGETS))

SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRCS))

# library objects = all objects except the main.o files
# MAIN_OBJS are the per-target main.o files derived from `TARGETS`.
MAIN_OBJS := $(patsubst %,$(OBJ_DIR)/%/main.o,$(TARGETS))
LIB_OBJS := $(filter-out $(MAIN_OBJS),$(OBJS))
# Build the explicit main binaries. Default target builds only `api` and `generator`.
all: $(MAIN_BINS)

# Build each binary from its main.o and the shared library objects
$(BIN_DIR)/%$(OUT_EXT): $(OBJ_DIR)/%/main.o $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Generic object rule
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean run

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

run: $(TARGET)
	$(TARGET)

.PHONY: test
# discover test sources recursively under tests/
# use find to allow subdirectories (tests/chomsky/foo.cpp -> bin/chomsky/foo)
TEST_SRCS := $(shell find tests -name '*.cpp')
# corresponding binaries under bin/ preserving subdirectory paths
TEST_BINS := $(patsubst tests/%.cpp,$(BIN_DIR)/%,$(TEST_SRCS))

# minimal set of objects tests typically need; adjust if tests depend on more
TEST_OBJS := $(OBJ_DIR)/automata/pta.o $(OBJ_DIR)/automata/dfa.o $(OBJ_DIR)/evaluator.o

test: $(TEST_BINS)
	@echo "Running tests..."
	@for t in $(TEST_BINS); do \
		echo "-> $$t"; \
		$$t || exit $$?; \
	done

$(BIN_DIR)/%$(OUT_EXT): tests/%.cpp $(TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) $<

.PHONY: windows
windows:
	@echo "Cross-compiling for Windows using prefix '$(CROSS_PREFIX)'."
	@if ! command -v $(CROSS_PREFIX)g++ >/dev/null 2>&1; then \
		echo "Error: cross-compiler '$(CROSS_PREFIX)g++' not found. Install mingw-w64 toolchain."; exit 1; \
	fi
	@echo "Cleaning previous build artifacts to avoid mixing host-built objects..."
	$(MAKE) clean
	$(MAKE) OUT_EXT=.exe CXX=$(CROSS_PREFIX)g++ all
