SRC_DIR := src
BUILD_DIR := build
TARGET := $(BUILD_DIR)/target.bc

CC := clang-13
CFLAGS := -Wall -Wextra -g
CPPFLAGS := -MMD -MP -Iinclude -I../klee-workdir/klee/include

SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
BCS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.bc,$(SRCS))
DEPS := $(BCS:.bc=.d)

all: $(TARGET)

$(TARGET): $(BCS)
	@mkdir -p $(dir $@)
	llvm-link-13 $(BCS) -o $@

$(BCS): $(BUILD_DIR)/%.bc: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -emit-llvm -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

-include $(DEPS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
