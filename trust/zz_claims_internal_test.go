// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"testing"
	"time"
)

// withClock runs f with claimNow returning *at. Not parallel: claimNow is
// package state.
func withClock(t *testing.T, at *time.Time) {
	t.Helper()
	prev := claimNow
	claimNow = func() time.Time { return *at }
	t.Cleanup(func() { claimNow = prev })
}

// A claim older than claimTTL no longer counts: the other node's report
// then waits on its own.
func TestClaimExpires(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	withClock(t, &now)
	c := newClaimSet()
	if c.claim(1, 2) != claimWaiting || !c.waiting(1, 2) {
		t.Fatal("first claim not waiting")
	}
	now = now.Add(claimTTL + time.Minute)
	if c.waiting(1, 2) {
		t.Fatal("an expired claim still waits")
	}
	if got := c.claim(2, 1); got != claimWaiting {
		t.Fatalf("the peer's claim after expiry: %v, want waiting", got)
	}
	if got := c.claim(1, 2); got != claimMatched {
		t.Fatalf("fresh claims from both: %v, want matched", got)
	}
	if c.size() != 0 || len(c.perNode) != 0 {
		t.Fatalf("matched claims left behind: size %d, counts %v", c.size(), c.perNode)
	}
}

// A node may have at most maxClaimsPerNode claims waiting; a renewed claim
// doesn't count twice, a matched or withdrawn one frees its place, and the
// sweep frees expired ones.
func TestClaimCap(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	withClock(t, &now)
	c := newClaimSet()
	c.lastSweep.Store(now.UnixNano()) // no background sweep during the test
	const from = 7
	for i := uint32(0); i < maxClaimsPerNode; i++ {
		if got := c.claim(from, 1000+i); got != claimWaiting {
			t.Fatalf("claim %d: %v", i, got)
		}
	}
	if got := c.claim(from, 1000); got != claimWaiting {
		t.Fatalf("renewing a claim: %v", got)
	}
	if got := c.claim(from, 99); got != claimRefused {
		t.Fatalf("past the cap: %v, want refused", got)
	}
	if c.claim(1000, from) != claimMatched || c.claim(from, 99) != claimWaiting {
		t.Fatal("a matched claim didn't free its place")
	}
	if !c.withdraw(from, 1001) || c.claim(from, 98) != claimWaiting {
		t.Fatal("a withdrawn claim didn't free its place")
	}
	// Others' claims are not limited by this node's.
	if c.claim(8, 1001) != claimWaiting {
		t.Fatal("another node's claim refused")
	}
	now = now.Add(claimTTL + time.Hour)
	c.sweep(now)
	if c.size() != 0 || len(c.perNode) != 0 {
		t.Fatalf("after the sweep: size %d, counts %d", c.size(), len(c.perNode))
	}
	if c.claim(from, 5000) != claimWaiting {
		t.Fatal("expired claims still hold the cap")
	}
}
