// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

// Regression for the per-IP rate-limiter bucket leak observed on
// 2026-05-26: RateLimiter.Cleanup() existed and worked, but was never
// invoked anywhere in the codebase despite its own comment ("Call
// periodically"). The only eviction path was the in-line one inside
// Allow(), which runs lazily when an unknown IP collides with a full
// bucket map — so under churn the map stayed pinned at maxBuckets and
// new legitimate IPs got rejected until an active bucket happened to go
// idle at the right moment to be evicted on the next collision.
//
// The fix wires RateLimiterCleanup() into the same reapLoop that
// already runs LogSamplerCleanup() every 10s. These tests pin both
// halves: (1) the Acceptor exposes the entry point, (2) Cleanup
// actually frees idle buckets, (3) the behaviour holds even when the
// map is at capacity (so legitimate IPs can land after a sweep).

import (
	"fmt"
	"testing"
	"time"
)

func TestAcceptorRateLimiterCleanupEvictsIdleBuckets(t *testing.T) {
	t.Parallel()

	a := NewAcceptor(100, nil)
	rl := a.rateLimiter

	clock := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return clock })

	for i := 0; i < 25; i++ {
		if !rl.Allow(fmt.Sprintf("10.0.0.%d", i)) {
			t.Fatalf("bucket %d unexpectedly denied during seed", i)
		}
	}
	if got := rl.BucketCount(); got != 25 {
		t.Fatalf("seed: bucket count = %d, want 25", got)
	}

	// Jump well past the eviction threshold (2 × window). With the
	// default 1-second window the threshold is 2 s; 30 s of idle is
	// firmly stale.
	clock = clock.Add(30 * time.Second)

	a.RateLimiterCleanup()
	if got := rl.BucketCount(); got != 0 {
		t.Fatalf("after cleanup: bucket count = %d, want 0 — eviction "+
			"did not run", got)
	}
}

func TestAcceptorRateLimiterCleanupKeepsActiveBuckets(t *testing.T) {
	t.Parallel()

	a := NewAcceptor(100, nil)
	rl := a.rateLimiter

	clock := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return clock })

	if !rl.Allow("203.0.113.1") {
		t.Fatalf("active IP denied on first request")
	}

	clock = clock.Add(500 * time.Millisecond)
	if !rl.Allow("203.0.113.1") {
		t.Fatalf("active IP denied on refresh")
	}

	clock = clock.Add(500 * time.Millisecond) // still inside 2 × window
	a.RateLimiterCleanup()

	if !rl.HasBucket("203.0.113.1") {
		t.Fatalf("active bucket evicted by cleanup — would force " +
			"every regular caller to rebuild state every 10 s")
	}
}

func TestAcceptorRateLimiterCleanupFreesSlotsAtCapacity(t *testing.T) {
	t.Parallel()
	// The scenario that motivated the fix: map is at maxBuckets,
	// the entries are old (idle attacker / past traffic burst), a
	// new legitimate IP arrives. Without Cleanup the in-line eviction
	// in Allow() does fire — but the test below verifies the Acceptor-
	// exposed cleanup path does the same work without needing a
	// collision to trigger it.

	rl := NewRateLimiter(5, 100*time.Millisecond, 3)

	clock := time.Unix(1_700_000_000, 0)
	rl.SetClock(func() time.Time { return clock })

	// Fill to capacity.
	for _, ip := range []string{"a", "b", "c"} {
		if !rl.Allow(ip) {
			t.Fatalf("seed: %s denied", ip)
		}
	}
	if got := rl.BucketCount(); got != 3 {
		t.Fatalf("seed: bucket count = %d, want 3", got)
	}

	// All three go idle past the eviction threshold.
	clock = clock.Add(time.Second)

	// Wrap in an Acceptor so we exercise the same entry point the
	// reapLoop uses.
	a := &Acceptor{rateLimiter: rl}
	a.RateLimiterCleanup()

	if got := rl.BucketCount(); got != 0 {
		t.Fatalf("post-cleanup at capacity: bucket count = %d, want 0", got)
	}

	// New IP must now be admitted without depending on collision-time eviction.
	if !rl.Allow("d") {
		t.Fatalf("post-cleanup: new IP denied at empty map")
	}
}
