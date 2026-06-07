// SPDX-License-Identifier: AGPL-3.0-or-later

package breakers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAllowDefaultsToClosedForUnknownName pins the most important
// safety invariant: an unknown breaker name returns Allow=true /
// state=Closed. A typo in either the file or the call site can
// never sever service.
func TestAllowDefaultsToClosedForUnknownName(t *testing.T) {
	t.Parallel()
	m := New()
	ok, st := m.Allow("registry.register")
	if !ok || st != Closed {
		t.Fatalf("Allow on unknown name = (%v, %v), want (true, Closed)", ok, st)
	}
}

// TestAllowReturnsStateForRegistered pins the three-way returns
// callers depend on to decide whether to log warn + proceed or to
// surface an error.
func TestAllowReturnsStateForRegistered(t *testing.T) {
	t.Parallel()
	m := New()
	m.Set("a.closed", Closed, "")
	m.Set("a.halfopen", HalfOpen, "soaking")
	m.Set("a.open", Open, "scheduled maintenance")

	cases := []struct {
		name      string
		wantAllow bool
		wantState State
	}{
		{"a.closed", true, Closed},
		{"a.halfopen", true, HalfOpen},
		{"a.open", false, Open},
	}
	for _, c := range cases {
		ok, st := m.Allow(c.name)
		if ok != c.wantAllow || st != c.wantState {
			t.Errorf("Allow(%q) = (%v, %v), want (%v, %v)",
				c.name, ok, st, c.wantAllow, c.wantState)
		}
	}
}

// TestReasonRoundTripsThroughManager pins that an operator-supplied
// reason survives Set → Reason. Error messages depend on this.
func TestReasonRoundTripsThroughManager(t *testing.T) {
	t.Parallel()
	m := New()
	m.Set("beacon.relay", Open, "spike test")
	if got := m.Reason("beacon.relay"); got != "spike test" {
		t.Fatalf("Reason = %q, want %q", got, "spike test")
	}
	if got := m.Reason("not.registered"); got != "" {
		t.Fatalf("Reason on unknown name = %q, want empty string", got)
	}
}

// TestParseStateAcceptsAliases pins the lenient on-disk vocabulary.
// half-open / halfopen are recognised as HalfOpen so manual edits
// don't fail closed; an unrecognised value yields an error so a typo
// surfaces instead of silently mapping to Closed.
func TestParseStateAcceptsAliases(t *testing.T) {
	t.Parallel()
	cases := map[string]State{
		"closed":    Closed,
		"":          Closed,
		"open":      Open,
		"OPEN":      Open,
		"half_open": HalfOpen,
		"half-open": HalfOpen,
		"halfopen":  HalfOpen,
		"  Open  ":  Open,
	}
	for in, want := range cases {
		got, err := ParseState(in)
		if err != nil {
			t.Errorf("ParseState(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseState(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseState("on"); err == nil {
		t.Errorf("ParseState(\"on\") returned no error; typo must surface")
	}
}

// TestReplaceAtomicallySwapsMap pins the watcher's required semantics:
// a single Replace call must publish every entry at once. Allow on
// names removed from the new map must revert to default-Closed; new
// names must be visible immediately.
func TestReplaceAtomicallySwapsMap(t *testing.T) {
	t.Parallel()
	m := New()
	m.Set("old.gate", Open, "stale")
	m.Replace(map[string]*Breaker{
		"new.gate":   {Name: "new.gate", State: Open, Reason: "fresh"},
		"other.gate": {Name: "other.gate", State: HalfOpen},
	})

	if ok, _ := m.Allow("old.gate"); !ok {
		t.Errorf("old.gate should default-Closed after Replace, got blocked")
	}
	if ok, st := m.Allow("new.gate"); ok || st != Open {
		t.Errorf("new.gate after Replace = (%v, %v), want (false, Open)", ok, st)
	}
	if ok, st := m.Allow("other.gate"); !ok || st != HalfOpen {
		t.Errorf("other.gate after Replace = (%v, %v), want (true, HalfOpen)", ok, st)
	}
	if got := m.Size(); got != 2 {
		t.Errorf("Size = %d, want 2", got)
	}
}

// ---- Watcher tests ----

func waitFor(total time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestWatcherMissingFileIsNotFatal pins the headline operational
// invariant: a missing breakers file is FINE. Process must keep
// running with the default-Closed Manager, watcher must keep
// polling without panic, and Allow on every name must remain
// (true, Closed).
func TestWatcherMissingFileIsNotFatal(t *testing.T) {
	t.Parallel()
	m := New()
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	go Watch(m, filepath.Join(dir, "absent.json"), 20*time.Millisecond, stop)
	time.Sleep(80 * time.Millisecond) // a few ticks
	if m.Size() != 0 {
		t.Fatalf("missing file: Size = %d, want 0", m.Size())
	}
	if ok, _ := m.Allow("anything"); !ok {
		t.Fatalf("missing file: Allow(\"anything\") = false, want true (default-Closed)")
	}
}

// TestWatcherInitialAndHotReload pins the happy path: an existing
// file at startup gets loaded; a later modification overwrites it.
func TestWatcherInitialAndHotReload(t *testing.T) {
	t.Parallel()
	m := New()
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")

	v1 := map[string]fileEntry{
		"registry.register": {State: "closed"},
		"beacon.punch":      {State: "open", Reason: "maintenance"},
	}
	if data, _ := json.Marshal(v1); os.WriteFile(path, data, 0o644) != nil {
		t.Fatal("write v1")
	}
	go Watch(m, path, 20*time.Millisecond, stop)

	if !waitFor(2*time.Second, func() bool { return m.Size() == 2 }) {
		t.Fatalf("v1 not applied; Size=%d", m.Size())
	}
	if ok, st := m.Allow("beacon.punch"); ok || st != Open {
		t.Fatalf("beacon.punch should be Open, got (%v, %v)", ok, st)
	}

	// v2: flip beacon.punch back to closed; drop the registry entry.
	v2 := map[string]fileEntry{
		"beacon.punch": {State: "closed"},
	}
	data, _ := json.Marshal(v2)
	if os.WriteFile(path, data, 0o644) != nil {
		t.Fatal("write v2")
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if !waitFor(2*time.Second, func() bool {
		return m.Size() == 1
	}) {
		t.Fatalf("v2 not applied; Size=%d", m.Size())
	}
	if ok, _ := m.Allow("registry.register"); !ok {
		t.Errorf("registry.register after v2 should be default-Closed, got blocked")
	}
	if ok, st := m.Allow("beacon.punch"); !ok || st != Closed {
		t.Errorf("beacon.punch after v2 = (%v, %v), want (true, Closed)", ok, st)
	}
}

// TestWatcherMalformedFileKeepsPreviousMap pins the fail-soft
// contract: a parse error must NOT clear the in-memory breaker map.
func TestWatcherMalformedFileKeepsPreviousMap(t *testing.T) {
	t.Parallel()
	m := New()
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")

	good := map[string]fileEntry{"a.gate": {State: "open", Reason: "x"}}
	data, _ := json.Marshal(good)
	if os.WriteFile(path, data, 0o644) != nil {
		t.Fatal("write good")
	}
	go Watch(m, path, 20*time.Millisecond, stop)
	if !waitFor(2*time.Second, func() bool { return m.Size() == 1 }) {
		t.Fatalf("good not applied; Size=%d", m.Size())
	}
	// Replace with malformed JSON.
	if os.WriteFile(path, []byte("{ not json"), 0o644) != nil {
		t.Fatal("write bad")
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	time.Sleep(120 * time.Millisecond)
	if m.Size() != 1 {
		t.Fatalf("malformed file cleared the map; Size=%d, want 1", m.Size())
	}
	if ok, st := m.Allow("a.gate"); ok || st != Open {
		t.Fatalf("a.gate after malformed reload = (%v, %v); want (false, Open)", ok, st)
	}
}

// TestAllowIsRaceFreeUnderConcurrentSet pins the safe-for-concurrent
// claim documented on Manager. Run many Allow goroutines while a
// writer thrashes the map; the race detector decides.
func TestAllowIsRaceFreeUnderConcurrentSet(t *testing.T) {
	t.Parallel()
	m := New()
	var wg sync.WaitGroup
	var stop atomic.Bool

	writer := func() {
		defer wg.Done()
		for !stop.Load() {
			m.Set("contended", Closed, "")
			m.Set("contended", Open, "x")
			m.Set("contended", HalfOpen, "y")
		}
	}
	reader := func() {
		defer wg.Done()
		for !stop.Load() {
			m.Allow("contended")
			m.Allow("never.registered")
		}
	}

	for i := 0; i < 4; i++ {
		wg.Add(2)
		go writer()
		go reader()
	}
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
