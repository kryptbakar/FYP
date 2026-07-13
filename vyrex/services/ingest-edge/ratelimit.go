// Per-agent ingest rate limiting — blunts a compromised/rogue agent flooding the
// pipeline (THREAT-MODEL TB1, DoS row). A token bucket per identity (mTLS CN, or
// remote address when TLS is off) caps sustained requests/sec with a burst
// allowance; over-quota requests get 429 before any parsing or publish work.
//
// Deliberately in-process and lock-simple: ingest-edge is horizontally scaled, so
// this is a per-replica guard, not a global quota (which would need the broker).
// Idle buckets are swept so memory can't grow with a churning agent fleet.
package main

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a per-key token bucket: `rate` tokens/sec refill up to `burst`.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64 // bucket capacity
	lastSwep time.Time
}

func newRateLimiter(ratePerSec, burst float64) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     ratePerSec,
		burst:    burst,
		lastSwep: time.Now(),
	}
}

// allow reports whether a request from `key` may proceed, consuming one token.
// A non-positive rate disables limiting (always allows).
func (rl *rateLimiter) allow(key string) bool {
	return rl.allowAt(key, time.Now())
}

// allowAt is allow() with an injectable clock, so the behaviour is unit-testable
// without sleeping.
func (rl *rateLimiter) allowAt(key string, now time.Time) bool {
	if rl.rate <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b := rl.buckets[key]
	if b == nil {
		// New identities start full so a legitimate first burst is never penalised.
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	// Refill proportionally to elapsed time, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = minFloat(rl.burst, b.tokens+elapsed*rl.rate)
		b.last = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	rl.sweep(now)
	return true
}

// sweep drops buckets untouched for a while so memory tracks the active fleet,
// not the historical one. Cheap and amortised (runs at most once per minute).
func (rl *rateLimiter) sweep(now time.Time) {
	if now.Sub(rl.lastSwep) < time.Minute {
		return
	}
	rl.lastSwep = now
	for k, b := range rl.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(rl.buckets, k)
		}
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
