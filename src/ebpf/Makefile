# Makefile — eBPF programs for OneInfinity
# Usage:
#   make          — compile all BPF objects
#   make clean    — remove compiled objects
#   make load     — load objects into /sys/fs/bpf/ (requires root + bpftool)
#   make attach   — print attach instructions for each program
#   make test     — run Docker BPF compile verification

CLANG   ?= clang
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BTF CO-RE compile flags
CFLAGS = -g -O2 -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. \
         -DBPF_NO_PRESERVE_ACCESS_INDEX \
         -c

BPF_SRCS := ssl_intercept.bpf.c \
            net_capture.bpf.c \
            key_extract.bpf.c \
            syscall_trace.bpf.c \
            process_inject_detect.bpf.c
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

.PHONY: all clean load attach test

all: $(BPF_OBJS)

ssl_intercept.bpf.o: ssl_intercept.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) ssl_intercept.bpf.c -o ssl_intercept.bpf.o

net_capture.bpf.o: net_capture.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) net_capture.bpf.c -o net_capture.bpf.o

key_extract.bpf.o: key_extract.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) key_extract.bpf.c -o key_extract.bpf.o

syscall_trace.bpf.o: syscall_trace.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) syscall_trace.bpf.c -o syscall_trace.bpf.o

process_inject_detect.bpf.o: process_inject_detect.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) process_inject_detect.bpf.c -o process_inject_detect.bpf.o

clean:
	rm -f *.bpf.o

# load — pins each program into the BPF filesystem (requires root)
load: all
	$(BPFTOOL) prog load ssl_intercept.bpf.o     /sys/fs/bpf/oi_ssl
	$(BPFTOOL) prog load net_capture.bpf.o        /sys/fs/bpf/oi_net
	$(BPFTOOL) prog load key_extract.bpf.o        /sys/fs/bpf/oi_key
	$(BPFTOOL) prog load syscall_trace.bpf.o      /sys/fs/bpf/oi_syscall
	$(BPFTOOL) prog load process_inject_detect.bpf.o /sys/fs/bpf/oi_inject

# attach — print attach instructions for manual wiring
attach: all
	@echo "=== OneInfinity eBPF attach instructions ==="
	@echo ""
	@echo "[ssl]      uprobe on SSL_write (all processes):"
	@echo "           bpftool prog attach pinned /sys/fs/bpf/oi_ssl uprobe <pid> <offset>"
	@echo ""
	@echo "[net]      XDP on a network interface (replace eth0 as needed):"
	@echo "           ip link set dev eth0 xdp obj net_capture.bpf.o sec xdp"
	@echo ""
	@echo "[key]      uprobes on AES_encrypt / RSA_private_encrypt / EVP_EncryptInit_ex:"
	@echo "           bpftool prog attach pinned /sys/fs/bpf/oi_key uprobe <pid> <offset>"
	@echo ""
	@echo "[syscall]  tracepoints (auto-attached via libbpf skeleton or bpftool):"
	@echo "           bpftool prog load syscall_trace.bpf.o /sys/fs/bpf/oi_syscall autoattach"
	@echo ""
	@echo "[inject]   kprobe + tracepoints (auto-attached via libbpf skeleton or bpftool):"
	@echo "           bpftool prog load process_inject_detect.bpf.o /sys/fs/bpf/oi_inject autoattach"

# test — run BPF compile verification inside a Docker container with kernel headers
test:
	docker exec -it oi-ebpf-dev sh -c \
	  "cd /src/ebpf && make clean && make all && echo 'BPF compile OK'"
