// Package governor provides a global concurrency governor that enforces
// aggregate throughput limits across all sidecars sharing the same scan
// context. This prevents individual per-sidecar caps from being bypassed
// by running many sidecars simultaneously against the same target.
//
// Usage:
//
//	gov := governor.NewGlobal(governor.LoadGlobalConfig())
//	if err := gov.Acquire(ctx, "oi-crawler"); err != nil {
//	    return err // budget exhausted or context cancelled
//	}
//	defer gov.Release("oi-crawler")
package governor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the global governor parameters.
type Config struct {
	// GlobalMaxConcurrent is the total number of in-flight cross-sidecar
	// operations allowed at any one time (across all sidecars, all targets).
	GlobalMaxConcurrent int

	// PerScanMaxConcurrent is the limit per scan_id.
	// Enforced via per-scan semaphores created lazily.
	PerScanMaxConcurrent int

	// PerTargetMaxConcurrent is the limit per target hostname.
	PerTargetMaxConcurrent int

	// MaxQueueWait is how long Acquire blocks before returning a timeout error.
	MaxQueueWait time.Duration
}

// LoadGlobalConfig reads config from environment variables with safe defaults.
//
//	GOVERNOR_GLOBAL_MAX       default 5000  (high-throughput offensive default)
//	GOVERNOR_PER_SCAN_MAX     default 500
//	GOVERNOR_PER_TARGET_MAX   default 200
//	GOVERNOR_QUEUE_WAIT_MS    default 30000 (30 s — time for large subnet scans)
func LoadGlobalConfig() Config {
	return Config{
		GlobalMaxConcurrent:    envInt("GOVERNOR_GLOBAL_MAX", 5000),
		PerScanMaxConcurrent:   envInt("GOVERNOR_PER_SCAN_MAX", 500),
		PerTargetMaxConcurrent: envInt("GOVERNOR_PER_TARGET_MAX", 200),
		MaxQueueWait:           time.Duration(envInt("GOVERNOR_QUEUE_WAIT_MS", 30000)) * time.Millisecond,
	}
}

// Global is the cross-sidecar concurrency governor.
type Global struct {
	cfg    Config
	global chan struct{} // global semaphore

	mu      sync.Mutex
	scans   map[string]chan struct{} // per-scan semaphores
	targets map[string]chan struct{} // per-target semaphores

	// Telemetry counters.
	acquired atomic.Int64
	rejected atomic.Int64
}

// NewGlobal creates a governor with the given config.
func NewGlobal(cfg Config) *Global {
	return &Global{
		cfg:     cfg,
		global:  make(chan struct{}, cfg.GlobalMaxConcurrent),
		scans:   make(map[string]chan struct{}),
		targets: make(map[string]chan struct{}),
	}
}

// Acquire blocks until a token is available globally, per-scan, and per-target.
// scanID and targetHost may be empty strings to skip those sub-limits.
// Returns an error if the context is cancelled or MaxQueueWait is exceeded.
func (g *Global) Acquire(ctx context.Context, sidecar, scanID, targetHost string) error {
	// Wrap context with our own queue-wait deadline.
	deadline := time.Now().Add(g.cfg.MaxQueueWait)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Global semaphore.
	select {
	case g.global <- struct{}{}:
	case <-ctx.Done():
		g.rejected.Add(1)
		return fmt.Errorf("governor: global limit reached for sidecar=%s: %w", sidecar, ctx.Err())
	}

	// Per-scan semaphore.
	if scanID != "" {
		sem := g.semaphoreFor(&g.scans, scanID, g.cfg.PerScanMaxConcurrent)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			<-g.global // release global
			g.rejected.Add(1)
			return fmt.Errorf("governor: per-scan limit reached scan=%s sidecar=%s: %w", scanID, sidecar, ctx.Err())
		}
	}

	// Per-target semaphore.
	if targetHost != "" {
		sem := g.semaphoreFor(&g.targets, targetHost, g.cfg.PerTargetMaxConcurrent)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			<-g.global
			if scanID != "" {
				<-g.semaphoreFor(&g.scans, scanID, g.cfg.PerScanMaxConcurrent)
			}
			g.rejected.Add(1)
			return fmt.Errorf("governor: per-target limit reached target=%s sidecar=%s: %w", targetHost, sidecar, ctx.Err())
		}
	}

	g.acquired.Add(1)
	return nil
}

// Release returns tokens for the given identifiers. Call with the same
// arguments used in the matching Acquire call.
func (g *Global) Release(sidecar, scanID, targetHost string) {
	<-g.global
	if scanID != "" {
		g.mu.Lock()
		if sem, ok := g.scans[scanID]; ok {
			select {
			case <-sem:
			default:
			}
		}
		g.mu.Unlock()
	}
	if targetHost != "" {
		g.mu.Lock()
		if sem, ok := g.targets[targetHost]; ok {
			select {
			case <-sem:
			default:
			}
		}
		g.mu.Unlock()
	}
}

// Stats returns current telemetry counters for observability.
func (g *Global) Stats() map[string]int64 {
	g.mu.Lock()
	activeScan := int64(len(g.scans))
	activeTarget := int64(len(g.targets))
	g.mu.Unlock()
	return map[string]int64{
		"global_in_flight":  int64(len(g.global)),
		"global_capacity":   int64(cap(g.global)),
		"active_scans":      activeScan,
		"active_targets":    activeTarget,
		"total_acquired":    g.acquired.Load(),
		"total_rejected":    g.rejected.Load(),
	}
}

// LogStats writes current stats to stderr — call periodically from a goroutine.
func (g *Global) LogStats(sidecar string) {
	s := g.Stats()
	log.Printf("[governor/%s] in_flight=%d cap=%d scans=%d targets=%d acquired=%d rejected=%d",
		sidecar, s["global_in_flight"], s["global_capacity"],
		s["active_scans"], s["active_targets"],
		s["total_acquired"], s["total_rejected"],
	)
}

// semaphoreFor lazily creates a per-key semaphore of the given capacity.
func (g *Global) semaphoreFor(m *map[string]chan struct{}, key string, cap int) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sem, ok := (*m)[key]; ok {
		return sem
	}
	sem := make(chan struct{}, cap)
	(*m)[key] = sem
	return sem
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
