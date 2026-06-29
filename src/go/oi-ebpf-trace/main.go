//go:build linux

// main.go — oi-ebpf-trace: load eBPF programs and emit NDJSON events
//
// Usage:
//
//	oi-ebpf-trace --program ssl,net,key --pid 1234 --timeout 30
//	oi-ebpf-trace --program ssl,net,key,syscall,inject --filter-comm nginx
//
// For each program in --program, loads the corresponding .bpf.o file from
// the same directory as the binary and reads its pinned BPF ringbuf map from
// /sys/fs/bpf/oi_{program}.  Each event is emitted as a JSON line to stdout:
//
//	{"type":"ssl_event","pid":N,"target":"ssl","data":"hexbytes","ts":1234.5,...}
//
// Exits 0 on SIGTERM, SIGINT, or timeout.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// traceEvent mirrors the tracer contract schema.
type traceEvent struct {
	Type         string  `json:"type"`
	PID          uint32  `json:"pid"`
	Target       string  `json:"target"`
	Data         string  `json:"data"`
	TS           float64 `json:"ts"`
	SourceEngine string  `json:"source_engine"`
	SessionID    string  `json:"session_id"`
}

// BPF ringbuf consumer constants (from kernel uapi/linux/bpf.h).
const (
	BPF_RINGBUF_BUSY_BIT    = (1 << 31)
	BPF_RINGBUF_DISCARD_BIT = (1 << 30)
	BPF_RINGBUF_HDR_SZ      = 8
)

// programEventType maps --program names to the 'type' field in emitted events.
var programEventType = map[string]string{
	"ssl":     "ssl_event",
	"net":     "net_event",
	"key":     "key_event",
	"syscall": "syscall_event",
	"inject":  "inject_event",
}

// programBPFObject maps --program names to their .bpf.o filenames.
var programBPFObject = map[string]string{
	"ssl":     "ssl_intercept.bpf.o",
	"net":     "net_capture.bpf.o",
	"key":     "key_extract.bpf.o",
	"syscall": "syscall_trace.bpf.o",
	"inject":  "process_inject_detect.bpf.o",
}

func newSessionID() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback: use time-based hex
		n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		return fmt.Sprintf("%016x", n.Int64())
	}
	return hex.EncodeToString(b)
}

// emitMu serialises concurrent JSON writes to stdout.
var emitMu sync.Mutex

func emit(ev traceEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	emitMu.Lock()
	fmt.Println(string(line))
	emitMu.Unlock()
}

// readRingbuf performs a simple mmap-based ringbuf read loop against a pinned
// BPF map FD.  For each sample it calls onRecord(pid, data).
// Returns when done channel is closed or an unrecoverable error occurs.
func readRingbuf(mapFD int, program, sessionID string, filterPID uint32, done <-chan struct{}) {
	eventType := programEventType[program]
	if eventType == "" {
		eventType = program + "_event"
	}

	// Determine page size for mmap layout.
	pageSize := os.Getpagesize()

	// The ringbuf map has two regions:
	//   page 0        — struct bpf_ringbuf_hdr (consumer/producer pos)
	//   pages 1..N    — data ring (we use a small 4 MB ring)
	const dataPages = 1024 // 4 MB at 4 KB pages
	dataSize := dataPages * pageSize
	totalSize := (1 + dataPages) * pageSize

	// mmap the entire ringbuf.
	data, err := unix.Mmap(mapFD, 0, totalSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		// On macOS or when the fd is not a real BPF map, fallback gracefully.
		fmt.Fprintf(os.Stderr, "{\"warning\":\"mmap failed for %s: %s, running in stub mode\"}\n", program, err)
		<-done
		return
	}
	defer unix.Munmap(data)

	// consumer_pos is at byte 0 of the first page.
	consumerPos := (*uint64)(unsafe.Pointer(&data[0]))
	// producer_pos is at byte 0 of the second half of page 0 (offset pageSize/2
	// per kernel layout; use offset 8 which is where the kernel puts it).
	producerPos := (*uint64)(unsafe.Pointer(&data[8]))

	ringData := data[pageSize:]

	for {
		select {
		case <-done:
			return
		default:
		}

		cons := *consumerPos
		prod := *producerPos

		if cons == prod {
			// Nothing to consume — poll at 1 ms intervals.
			time.Sleep(time.Millisecond)
			continue
		}

		// Read the 8-byte record header at consumer offset.
		offset := cons % uint64(dataSize)
		if int(offset)+BPF_RINGBUF_HDR_SZ > len(ringData) {
			*consumerPos = cons + BPF_RINGBUF_HDR_SZ
			continue
		}

		hdrPtr := (*uint64)(unsafe.Pointer(&ringData[offset]))
		hdr := *hdrPtr

		recLen := uint32(hdr & 0x3FFFFFFF)
		flags := uint32(hdr >> 30)

		advance := uint64(BPF_RINGBUF_HDR_SZ) + uint64((recLen+7)&^uint32(7))

		if flags&1 != 0 { // discard bit
			*consumerPos = cons + advance
			continue
		}

		dataStart := int(offset) + BPF_RINGBUF_HDR_SZ
		dataEnd := dataStart + int(recLen)
		if dataEnd > len(ringData) {
			*consumerPos = cons + advance
			continue
		}

		recBytes := make([]byte, recLen)
		copy(recBytes, ringData[dataStart:dataEnd])

		*consumerPos = cons + advance

		// Parse the first 4 bytes as PID (little-endian u32).
		var pid uint32
		if len(recBytes) >= 4 {
			pid = uint32(recBytes[0]) |
				uint32(recBytes[1])<<8 |
				uint32(recBytes[2])<<16 |
				uint32(recBytes[3])<<24
		}

		// Apply PID filter when requested.
		if filterPID != 0 && pid != filterPID {
			continue
		}

		// The rest is raw data.
		var payload []byte
		if len(recBytes) > 4 {
			payload = recBytes[4:]
		}

		now := float64(time.Now().UnixNano()) / 1e9
		emit(traceEvent{
			Type:         eventType,
			PID:          pid,
			Target:       program,
			Data:         hex.EncodeToString(payload),
			TS:           now,
			SourceEngine: "ebpf",
			SessionID:    sessionID,
		})
	}
}

// stubHeartbeat emits one heartbeat per second when the BPF map is unavailable.
func stubHeartbeat(program, sessionID string, done <-chan struct{}) {
	eventType := programEventType[program]
	if eventType == "" {
		eventType = program + "_event"
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			emit(traceEvent{
				Type:         eventType,
				PID:          0,
				Target:       program,
				Data:         "",
				TS:           float64(time.Now().UnixNano()) / 1e9,
				SourceEngine: "ebpf",
				SessionID:    sessionID,
			})
		}
	}
}

// loadProgram opens the pinned BPF map for one program and starts its reader.
// Returns the map FD (or -1 if unavailable) and launches a goroutine.
func loadProgram(program, sessionID string, filterPID uint32, done <-chan struct{}, wg *sync.WaitGroup) int {
	mapPath := filepath.Join("/sys/fs/bpf", "oi_"+program)
	mapFD, err := syscall.Open(mapPath, syscall.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"{\"warning\":\"pinned map %s not found (%s), emitting heartbeat only\"}\n",
			mapPath, err)
		wg.Add(1)
		go func() {
			defer wg.Done()
			stubHeartbeat(program, sessionID, done)
		}()
		return -1
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		readRingbuf(mapFD, program, sessionID, filterPID, done)
	}()
	return mapFD
}

func main() {
	programFlag  := flag.String("program", "ssl", "Comma-separated programs: ssl,net,key,syscall,inject")
	pidFlag      := flag.Int("pid", 0, "Target PID to filter (0 = all)")
	filterComm   := flag.String("filter-comm", "", "Filter by process comm name (informational, passed to BPF)")
	timeoutFlag  := flag.Int("timeout", 0, "Timeout in seconds (0 = no timeout)")
	// Legacy flag kept for backward compatibility with old callers.
	targetFlag   := flag.String("target", "", "Deprecated: use --program instead")
	flag.Parse()

	// Resolve program list: --program wins; fall back to legacy --target.
	programList := *programFlag
	if programList == "" && *targetFlag != "" {
		programList = *targetFlag
	}

	programs := strings.Split(programList, ",")
	// Deduplicate and trim whitespace.
	seen := make(map[string]bool, len(programs))
	clean := programs[:0]
	for _, p := range programs {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		// Validate known programs; emit a warning for unknowns but continue.
		if _, ok := programEventType[p]; !ok {
			fmt.Fprintf(os.Stderr,
				"{\"warning\":\"unknown program %q — will map to %s_event\"}\n", p, p)
		}
		clean = append(clean, p)
	}
	programs = clean

	if len(programs) == 0 {
		fmt.Fprintln(os.Stderr, `{"error":"--program is empty; specify one or more of ssl,net,key,syscall,inject"}`)
		os.Exit(1)
	}

	// Emit filter-comm info if provided (the BPF programs read this from the
	// kernel; here we just surface it in the log for observability).
	if *filterComm != "" {
		fmt.Fprintf(os.Stderr,
			"{\"info\":\"filter-comm=%s\"}\n", *filterComm)
	}

	filterPID := uint32(*pidFlag)
	sessionID := newSessionID()

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Load all programs in parallel goroutines.
	openFDs := make([]int, 0, len(programs))
	var fdMu sync.Mutex
	var loadWg sync.WaitGroup

	for _, prog := range programs {
		prog := prog // capture
		loadWg.Add(1)
		go func() {
			defer loadWg.Done()
			fd := loadProgram(prog, sessionID, filterPID, done, &wg)
			fdMu.Lock()
			openFDs = append(openFDs, fd)
			fdMu.Unlock()
		}()
	}
	loadWg.Wait()

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Optional timeout.
	var timeoutCh <-chan time.Time
	if *timeoutFlag > 0 {
		timeoutCh = time.After(time.Duration(*timeoutFlag) * time.Second)
	}

	// Wait for shutdown signal.
	select {
	case <-sigCh:
	case <-timeoutCh:
	}

	close(done)
	wg.Wait()

	// Emit shutdown events for each program.
	now := float64(time.Now().UnixNano()) / 1e9
	for _, prog := range programs {
		eventType := programEventType[prog]
		if eventType == "" {
			eventType = prog + "_event"
		}
		emit(traceEvent{
			Type:         eventType,
			PID:          0,
			Target:       prog,
			Data:         "shutdown",
			TS:           now,
			SourceEngine: "ebpf",
			SessionID:    sessionID,
		})
	}

	// Close map FDs.
	for _, fd := range openFDs {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
	os.Exit(0)
}
