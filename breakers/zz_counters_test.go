// SPDX-License-Identifier: AGPL-3.0-or-later

package breakers

import (
	"sync"
	"testing"
	"time"
)

// TestAllow_CountsAllowedAndDenied pins the contract that every Allow
// call updates the per-name counters — including for names that have
// no registered breaker. Operators rely on the allowed-on-ungated count
// to know a gate is seeing traffic before they flip it.
func TestAllow_CountsAllowedAndDenied(t *testing.T) {
	t.Parallel()
	m := New()

	// Hit an unknown name 5 times — all should count as allowed.
	for i := 0; i < 5; i++ {
		ok, _ := m.Allow("registry.unknown")
		if !ok {
			t.Fatalf("default-allow on unknown name: got deny on iter %d", i)
		}
	}

	// Register Open and hit 3 times — all should count as denied.
	m.Set("registry.gated", Open, "test")
	for i := 0; i < 3; i++ {
		ok, _ := m.Allow("registry.gated")
		if ok {
			t.Fatalf("Open breaker allowed traffic on iter %d", i)
		}
	}

	stats := m.StatsSnapshot()
	byName := make(map[string]Stats)
	for _, s := range stats {
		byName[s.Name] = s
	}

	if got := byName["registry.unknown"].AllowedTotal; got != 5 {
		t.Errorf("unknown.allowed_total = %d, want 5", got)
	}
	if got := byName["registry.unknown"].DeniedTotal; got != 0 {
		t.Errorf("unknown.denied_total = %d, want 0", got)
	}
	if got := byName["registry.gated"].AllowedTotal; got != 0 {
		t.Errorf("gated.allowed_total = %d, want 0", got)
	}
	if got := byName["registry.gated"].DeniedTotal; got != 3 {
		t.Errorf("gated.denied_total = %d, want 3", got)
	}
	if byName["registry.gated"].LastDeniedAt == nil {
		t.Errorf("gated.last_denied_at not set despite denials")
	}
}

// TestAllow_ConcurrentCounters confirms the hot-path counter increments
// stay accurate under concurrent Allow calls. Without atomic ops or
// with a lost-update on the sync.Map LoadOrStore, the sum would drift.
func TestAllow_ConcurrentCounters(t *testing.T) {
	t.Parallel()
	m := New()
	const goroutines = 50
	const perGoroutine = 1000
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				m.Allow("registry.hotpath")
			}
		}()
	}
	wg.Wait()
	want := int64(goroutines * perGoroutine)
	stats := m.StatsSnapshot()
	for _, s := range stats {
		if s.Name == "registry.hotpath" {
			if s.AllowedTotal != want {
				t.Errorf("allowed_total = %d, want %d (lost updates?)", s.AllowedTotal, want)
			}
			return
		}
	}
	t.Errorf("registry.hotpath missing from snapshot")
}

// TestStatsSnapshot_StableOrdering pins that snapshot order is stable
// (sorted by name) so operator dashboards don't shuffle rows on every
// refresh. A test rather than just an internal sort.Slice because the
// order is part of the API contract.
func TestStatsSnapshot_StableOrdering(t *testing.T) {
	t.Parallel()
	m := New()
	m.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	names := []string{"zeta.last", "alpha.first", "middle.thing"}
	for _, n := range names {
		m.Allow(n)
	}
	got := m.StatsSnapshot()
	want := []string{"alpha.first", "middle.thing", "zeta.last"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("[%d] = %q, want %q (sort drift)", i, got[i].Name, w)
		}
	}
}

// TestDelete_KeepsCounters confirms removing a breaker does NOT zero
// the counters. Operators reading post-incident need the allowed +
// denied totals to remain visible after they revert the override.
func TestDelete_KeepsCounters(t *testing.T) {
	t.Parallel()
	m := New()
	m.Set("registry.removeme", Open, "test")
	for i := 0; i < 7; i++ {
		m.Allow("registry.removeme")
	}
	m.Delete("registry.removeme")

	stats := m.StatsSnapshot()
	for _, s := range stats {
		if s.Name == "registry.removeme" {
			if s.DeniedTotal != 7 {
				t.Errorf("denied_total after delete = %d, want 7", s.DeniedTotal)
			}
			if s.State != "closed" {
				t.Errorf("state after delete = %q, want closed (default)", s.State)
			}
			return
		}
	}
	t.Errorf("registry.removeme missing from snapshot after delete")
}
