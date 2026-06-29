package governor_test

import (
	"context"
	"testing"
	"time"

	"github.com/oneinfinity/oi-sdk/governor"
)

func defaultCfg() governor.Config {
	return governor.Config{
		GlobalMaxConcurrent:    5,
		PerScanMaxConcurrent:   3,
		PerTargetMaxConcurrent: 2,
		MaxQueueWait:           200 * time.Millisecond,
	}
}

func TestAcquireRelease(t *testing.T) {
	g := governor.NewGlobal(defaultCfg())
	ctx := context.Background()

	if err := g.Acquire(ctx, "oi-recon-probe", "scan-1", "target.com"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g.Release("oi-recon-probe", "scan-1", "target.com")

	stats := g.Stats()
	if stats["global_in_flight"] != 0 {
		t.Errorf("expected 0 in-flight after release, got %d", stats["global_in_flight"])
	}
}

func TestGlobalLimitEnforced(t *testing.T) {
	g := governor.NewGlobal(defaultCfg()) // cap=5
	ctx := context.Background()

	// Fill global capacity.
	for i := 0; i < 5; i++ {
		if err := g.Acquire(ctx, "oi-crawler", "", ""); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	// 6th acquire must fail within MaxQueueWait.
	shortCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := g.Acquire(shortCtx, "oi-crawler", "", "")
	if err == nil {
		t.Fatal("expected error when global limit exceeded, got nil")
	}
}

func TestPerTargetLimitEnforced(t *testing.T) {
	g := governor.NewGlobal(defaultCfg()) // per-target cap=2
	ctx := context.Background()

	if err := g.Acquire(ctx, "a", "s1", "host.com"); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := g.Acquire(ctx, "a", "s2", "host.com"); err != nil {
		t.Fatalf("second acquire: %v", err)
	}

	// Third acquire against same target must fail.
	shortCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.Acquire(shortCtx, "a", "s3", "host.com"); err == nil {
		t.Fatal("expected per-target limit error, got nil")
	}
}

func TestPerScanLimitEnforced(t *testing.T) {
	g := governor.NewGlobal(defaultCfg()) // per-scan cap=3
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := g.Acquire(ctx, "a", "scan-x", ""); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	shortCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := g.Acquire(shortCtx, "a", "scan-x", ""); err == nil {
		t.Fatal("expected per-scan limit error, got nil")
	}
}

func TestStatsCounters(t *testing.T) {
	g := governor.NewGlobal(defaultCfg())
	ctx := context.Background()

	if err := g.Acquire(ctx, "x", "s", "t"); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	stats := g.Stats()
	if stats["total_acquired"] != 1 {
		t.Errorf("expected acquired=1, got %d", stats["total_acquired"])
	}
	if stats["global_in_flight"] != 1 {
		t.Errorf("expected in_flight=1, got %d", stats["global_in_flight"])
	}
	g.Release("x", "s", "t")
}

func TestRejectedCounter(t *testing.T) {
	g := governor.NewGlobal(defaultCfg()) // global cap=5
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = g.Acquire(ctx, "x", "", "")
	}
	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_ = g.Acquire(shortCtx, "x", "", "")

	stats := g.Stats()
	if stats["total_rejected"] < 1 {
		t.Errorf("expected at least 1 rejected, got %d", stats["total_rejected"])
	}
}

func TestEmptyScanAndTarget(t *testing.T) {
	// Acquire/Release with empty scanID and targetHost must not panic.
	g := governor.NewGlobal(defaultCfg())
	ctx := context.Background()
	if err := g.Acquire(ctx, "probe", "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g.Release("probe", "", "")
}
