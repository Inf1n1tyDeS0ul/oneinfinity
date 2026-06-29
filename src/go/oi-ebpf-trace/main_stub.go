//go:build !linux

// main_stub.go — non-Linux stub for oi-ebpf-trace
// eBPF ringbuf access requires a Linux kernel; this stub allows the module
// to compile on macOS/Windows for CI purposes.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println(`{"error":"oi-ebpf-trace requires Linux"}`)
	os.Exit(1)
}
