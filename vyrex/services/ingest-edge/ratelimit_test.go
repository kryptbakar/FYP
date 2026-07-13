package main

import (
	"testing"
	"time"
)

func TestRateLimiterBurstThenBlock(t *testing.T) {
	rl := newRateLimiter(10, 5) // 10/s refill, burst 5
	now := time.Unix(0, 0)
	// First 5 requests (the burst) succeed with no time advance.
	for i := 0; i < 5; i++ {
		if !rl.allowAt("agent-1", now) {
			t.Fatalf("request %d in burst was blocked", i)
		}
	}
	// 6th within the same instant must be blocked.
	if rl.allowAt("agent-1", now) {
		t.Fatal("expected 6th request to be rate-limited")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := newRateLimiter(10, 5)
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		rl.allowAt("a", now)
	}
	if rl.allowAt("a", now) {
		t.Fatal("bucket should be empty")
	}
	// After 0.3s at 10/s, ~3 tokens refill.
	later := now.Add(300 * time.Millisecond)
	got := 0
	for i := 0; i < 5; i++ {
		if rl.allowAt("a", later) {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("expected 3 refilled tokens, got %d", got)
	}
}

func TestRateLimiterIsPerAgent(t *testing.T) {
	rl := newRateLimiter(1, 2)
	now := time.Unix(0, 0)
	// Exhaust agent-a's bucket.
	rl.allowAt("a", now)
	rl.allowAt("a", now)
	if rl.allowAt("a", now) {
		t.Fatal("agent a should be limited")
	}
	// agent-b is unaffected.
	if !rl.allowAt("b", now) {
		t.Fatal("agent b should have its own bucket")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := newRateLimiter(0, 0) // rate<=0 disables
	now := time.Unix(0, 0)
	for i := 0; i < 1000; i++ {
		if !rl.allowAt("x", now) {
			t.Fatal("disabled limiter must always allow")
		}
	}
}
