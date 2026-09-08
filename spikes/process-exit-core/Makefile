CLANG ?= clang
LLVM_READELF ?= llvm-readelf
BPFTOOL ?= bpftool
BTF ?= /sys/kernel/btf/vmlinux
BUILD_DIR ?= build
OBJECT := $(BUILD_DIR)/process_exit.bpf.o
MIN_BTF := $(BUILD_DIR)/process_exit.min.btf

.PHONY: all verify clean

all: $(OBJECT)

$(BUILD_DIR):
	mkdir -p $@

$(OBJECT): process_exit.bpf.c | $(BUILD_DIR)
	$(CLANG) -target bpfel -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror -c $< -o $@

verify: $(OBJECT)
	$(LLVM_READELF) --sections $(OBJECT) | grep -q '\.BTF'
	$(LLVM_READELF) --sections $(OBJECT) | grep -q '\.BTF\.ext'
	$(BPFTOOL) gen min_core_btf $(BTF) $(MIN_BTF) $(OBJECT)
	test -s $(MIN_BTF)

clean:
	rm -rf $(BUILD_DIR)
