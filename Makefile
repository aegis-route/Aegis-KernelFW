# Makefile for Aegis-KernelFW (XDP/eBPF Firewall)

CC ?= gcc
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

INC_DIR := include
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
USER_DIR := $(SRC_DIR)/userspace
BUILD_DIR := build

BPF_SRC := $(BPF_DIR)/xdp_fw.bpf.c
BPF_OBJ := $(BUILD_DIR)/xdp_fw.bpf.o

USER_SRCS := $(USER_DIR)/main.c $(USER_DIR)/loader.c $(USER_DIR)/rule_manager.c $(USER_DIR)/stats.c
USER_OBJS := $(patsubst $(USER_DIR)/%.c,$(BUILD_DIR)/%.o,$(USER_SRCS))
TARGET_BIN := $(BUILD_DIR)/aegis-fw

LIBS := -lbpf -lelf -lz

.PHONY: all bpf user clean install check-deps help

all: check-deps bpf user
	@echo ""
	@echo "=========================================================="
	@echo " [✓] Build Complete!"
	@echo "  - eBPF Object: $(BPF_OBJ)"
	@echo "  - CLI Utility: $(TARGET_BIN)"
	@echo " Run 'sudo ./$(TARGET_BIN) help' to view available options."
	@echo "=========================================================="

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# 1. Compile Kernel eBPF Code
bpf: $(BUILD_DIR) $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(INC_DIR)/aegis_types.h $(INC_DIR)/aegis_common.h $(wildcard $(BPF_DIR)/mitigation/*.h)
	@echo "[CLANG] Compiling eBPF program: $< -> $@"
	$(CLANG) $(BPF_CFLAGS) -I$(INC_DIR) -I$(BPF_DIR) -c $< -o $@
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 && $(LLVM_STRIP) -g $@ || true

# 2. Compile Userspace Control Plane
user: $(BUILD_DIR) $(TARGET_BIN)

$(BUILD_DIR)/%.o: $(USER_DIR)/%.c
	@echo "[GCC] Compiling userspace object: $< -> $@"
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(USER_DIR) -c $< -o $@

$(TARGET_BIN): $(USER_OBJS)
	@echo "[LINK] Linking binary: $@"
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(USER_DIR) $^ $(LIBS) -o $@

# Check Dependencies
check-deps:
	@echo "[*] Checking build toolchain..."
	@which $(CLANG) >/dev/null 2>&1 || (echo "[!] Error: '$(CLANG)' is not installed. Run 'sudo bash scripts/setup_deps.sh' or 'sudo apt install clang llvm libbpf-dev'"; exit 1)
	@pkg-config --exists libbpf 2>/dev/null || (ldconfig -p | grep libbpf >/dev/null 2>&1) || (echo "[!] Error: libbpf development headers missing. Run 'sudo bash scripts/setup_deps.sh'"; exit 1)
	@echo "[✓] Toolchain verified."

install: all
	@echo "[*] Installing Aegis-KernelFW to system..."
	install -d /usr/local/bin
	install -d /usr/local/lib/aegis
	install -m 755 $(TARGET_BIN) /usr/local/bin/aegis-fw
	install -m 644 $(BPF_OBJ) /usr/local/lib/aegis/xdp_fw.bpf.o
	@echo "[✓] Installed: /usr/local/bin/aegis-fw"
	@echo "[✓] Installed: /usr/local/lib/aegis/xdp_fw.bpf.o"

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "[✓] Done."

help:
	@echo "Aegis-KernelFW Build System"
	@echo "Targets:"
	@echo "  make all          - Build eBPF object and userspace CLI"
	@echo "  make bpf          - Build only eBPF kernel program"
	@echo "  make user         - Build only userspace CLI daemon"
	@echo "  make install      - Install binary & BPF object to /usr/local"
	@echo "  make clean        - Remove all build artifacts"
	@echo "  make check-deps   - Verify required compilers and libraries"
