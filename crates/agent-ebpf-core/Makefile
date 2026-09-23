CLANG ?= clang
TARGET_ARCH ?= x86
BUILD_DIR ?= build
OBJECT := $(BUILD_DIR)/process-exit.bpf.o

.PHONY: all clean

all: $(OBJECT)

$(BUILD_DIR):
	mkdir -p $@

$(OBJECT): process_exit.bpf.c | $(BUILD_DIR)
	$(CLANG) -target bpfel -D__TARGET_ARCH_$(TARGET_ARCH) -O2 -g -Wall -Werror -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
