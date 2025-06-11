# Makefile
ARCH := $(shell uname -m)
TARGET := amd64
ARCH_FLAGS := -D__TARGET_ARCH_x86

ifeq ($(ARCH),aarch64)
    TARGET := arm64
    ARCH_FLAGS := -D__TARGET_ARCH_arm64
endif

ifeq ($(ARCH),arm64)
    TARGET := arm64
    ARCH_FLAGS := -D__TARGET_ARCH_arm64
endif

.PHONY: vmlinux generate build clean run

vmlinux:
	@if [ ! -f ebpf/vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h; \
	else \
		echo "vmlinux.h already exists, skipping generation"; \
	fi

generate: vmlinux
	@echo "Generating eBPF Go bindings for $(TARGET) architecture..."
	go run github.com/cilium/ebpf/cmd/bpf2go \
	    -go-package main \
		-cc clang \
		-target $(TARGET) \
		-output-dir cmd \
		-cflags "-O2 -g -gdwarf-4 -Wall $(ARCH_FLAGS) -I./ebpf -D__USE_ATTRIBUTES__ -target bpf -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option" \
		tls ./ebpf/tls_probe.c

build: generate
	go build -o tls-capture ./cmd/

clean:
	rm -f cmd/tls_x86*.go cmd/tls_x86*.o
	rm -f tls-capture

clean-all: clean
	rm -f ebpf/vmlinux.h

run: build
	sudo ./tls-capture