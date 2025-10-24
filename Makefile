SRC_DIR := src
BUILD_DIR := build
TARGET := $(BUILD_DIR)/target.bc
REPLAY := $(BUILD_DIR)/replay.out

CLANG := clang-13
GCC := gcc
CPPFLAGS := -MMD -MP -Iinclude -I../klee-workdir/klee/include
CFLAGS := -Wall -Wextra -g
LDFLAGS := -L../klee-workdir/klee/build/lib
LDLIBS := -lkleeRuntest

SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
BCS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.bc,$(SRCS))
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(BCS:.bc=.d)

all: $(TARGET) $(REPLAY)

$(TARGET): $(BCS)
	@mkdir -p $(dir $@)
	llvm-link-13 -o $@ $(BCS)

$(REPLAY): $(OBJS)
	@mkdir -p $(dir $@)
	$(GCC) $(LDFLAGS) -o $(@) $(OBJS) $(LDLIBS)

$(BCS): $(BUILD_DIR)/%.bc: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CLANG) $(CPPFLAGS) $(CFLAGS) -emit-llvm -c -o $@ $<

$(OBJS): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(GCC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
