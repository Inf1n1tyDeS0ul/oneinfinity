// Package budget provides token-bucket semaphores and FD tracking for
// sidecar resource budgets.
package budget

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Semaphore — weighted token bucket with context cancellation.
// ---------------------------------------------------------------------------

// Semaphore limits concurrent access to a shared resource.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a Semaphore with capacity n.
func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
}

// Acquire blocks until a token is available or ctx is cancelled.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a token. Panics if called more times than Acquire succeeded.
func (s *Semaphore) Release() {
	select {
	case <-s.ch:
	default:
		panic("budget: Semaphore.Release called without a matching Acquire")
	}
}

// Available returns the current free-token count.
func (s *Semaphore) Available() int { return cap(s.ch) - len(s.ch) }

// ---------------------------------------------------------------------------
// PerHostLimiter — per-hostname connection limits with automatic eviction.
// ---------------------------------------------------------------------------

// hostEntry pairs a semaphore with a reference count so entries can be
// removed from the map when no goroutine holds or awaits a slot.
type hostEntry struct {
	sem  *Semaphore
	refs int // number of goroutines that have called Acquire (waiting or holding)
}

// PerHostLimiter maintains a Semaphore per unique hostname, created lazily
// and evicted automatically once all connections for that host are released.
// The map is therefore bounded by the number of concurrently-active hosts,
// not the number of distinct hosts ever seen.
type PerHostLimiter struct {
	mu    sync.Mutex
	limit int
	hosts map[string]*hostEntry
}

// NewPerHostLimiter creates a limiter where each host is capped at limit
// concurrent connections.
func NewPerHostLimiter(limit int) *PerHostLimiter {
	return &PerHostLimiter{
		limit: limit,
		hosts: make(map[string]*hostEntry),
	}
}

// Acquire blocks until a slot is free for host, or ctx is cancelled.
// The entry is created on first use and removed when the last caller releases.
func (p *PerHostLimiter) Acquire(ctx context.Context, host string) error {
	// Register intent under the lock, then wait outside it so we don't hold
	// the mutex while blocked on the semaphore.
	p.mu.Lock()
	e, ok := p.hosts[host]
	if !ok {
		e = &hostEntry{sem: NewSemaphore(p.limit)}
		p.hosts[host] = e
	}
	e.refs++
	p.mu.Unlock()

	if err := e.sem.Acquire(ctx); err != nil {
		// Context cancelled before we got a slot — unregister intent.
		p.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(p.hosts, host)
		}
		p.mu.Unlock()
		return err
	}
	return nil
}

// Release returns a slot for host and evicts the map entry if no other
// goroutine is waiting or holding a slot for that host.
func (p *PerHostLimiter) Release(host string) {
	p.mu.Lock()
	e := p.hosts[host]
	if e == nil {
		p.mu.Unlock()
		return
	}
	e.sem.Release()
	e.refs--
	if e.refs == 0 {
		delete(p.hosts, host)
	}
	p.mu.Unlock()
}

// ActiveHosts returns the number of hosts currently tracked (for diagnostics).
func (p *PerHostLimiter) ActiveHosts() int {
	p.mu.Lock()
	n := len(p.hosts)
	p.mu.Unlock()
	return n
}

// ---------------------------------------------------------------------------
// FDBudget — global file-descriptor counter.
// ---------------------------------------------------------------------------

// FDBudget enforces a ceiling on concurrently-open file descriptors.
type FDBudget struct {
	current atomic.Int64
	max     int64
}

// NewFDBudget creates a budget capped at max descriptors.
func NewFDBudget(max int) *FDBudget {
	return &FDBudget{max: int64(max)}
}

// Acquire increments the FD counter, returning an error if the limit is
// already reached. If ctx is cancelled before a slot opens this returns
// ctx.Err() — callers that want blocking behaviour should wrap in a retry loop.
func (f *FDBudget) Acquire(ctx context.Context) error {
	for {
		cur := f.current.Load()
		if cur >= f.max {
			// Non-blocking path: respect context cancellation.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("budget: FD limit %d reached", f.max)
			}
		}
		if f.current.CompareAndSwap(cur, cur+1) {
			return nil
		}
		// CAS race — retry immediately.
	}
}

// Release decrements the FD counter.
func (f *FDBudget) Release() { f.current.Add(-1) }

// Used returns the current count of acquired descriptors.
func (f *FDBudget) Used() int64 { return f.current.Load() }
