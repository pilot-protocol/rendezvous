// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/rendezvous/accept"
)

// recordedSet is a fake of (*Server).SetRateLimitWhitelist that records
// what the watcher passes through. Concurrent-safe; the watcher runs in
// its own goroutine.
type recordedSet struct {
	mu      sync.Mutex
	calls   int32
	last    []accept.WhitelistEntry
	failErr error
}

func (r *recordedSet) set(entries []accept.WhitelistEntry) error {
	atomic.AddInt32(&r.calls, 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = append([]accept.WhitelistEntry(nil), entries...)
	return r.failErr
}

func (r *recordedSet) callCount() int32 { return atomic.LoadInt32(&r.calls) }

func (r *recordedSet) snapshot() []accept.WhitelistEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]accept.WhitelistEntry(nil), r.last...)
}

// waitFor polls cond every 10 ms up to total. Returns true if cond
// returned true; false on timeout. Used so tests don't sleep for fixed
// durations longer than necessary.
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

// TestWatcherMissingFileIsFineDoesNotBlock pins the most important
// operational invariant: a missing whitelist file is not an error and
// must not crash, panic, or block the watcher loop.
func TestWatcherMissingFileIsFineDoesNotBlock(t *testing.T) {
	t.Parallel()
	rec := &recordedSet{}
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	go watchRateLimitWhitelist(filepath.Join(dir, "missing.json"),
		20*time.Millisecond, rec.set, stop)
	time.Sleep(80 * time.Millisecond) // let several ticks pass
	if got := rec.callCount(); got != 0 {
		t.Fatalf("set called %d times against a missing file; want 0", got)
	}
}

// TestWatcherInitialApplyAndHotReload pins the happy path: an
// existing file at startup gets loaded; a later modification reloads
// the new contents.
func TestWatcherInitialApplyAndHotReload(t *testing.T) {
	t.Parallel()
	rec := &recordedSet{}
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.json")

	v1 := []whitelistFileEntry{{CIDR: "10.128.0.0/9", Rate: 50000}}
	if data, _ := json.Marshal(v1); os.WriteFile(path, data, 0o644) != nil {
		t.Fatalf("write v1")
	}
	go watchRateLimitWhitelist(path, 20*time.Millisecond, rec.set, stop)

	if !waitFor(2*time.Second, func() bool {
		s := rec.snapshot()
		return len(s) == 1 && s[0].CIDR == "10.128.0.0/9" && s[0].Rate == 50000
	}) {
		t.Fatalf("initial apply did not propagate v1; last=%+v", rec.snapshot())
	}

	v2 := []whitelistFileEntry{
		{CIDR: "10.128.0.0/9", Rate: 50000},
		{CIDR: "35.238.109.166/32", Rate: 5000},
	}
	// Force a future mtime so the watcher observes a change even on FS
	// with low-resolution timestamps.
	if data, _ := json.Marshal(v2); os.WriteFile(path, data, 0o644) != nil {
		t.Fatalf("write v2")
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	if !waitFor(2*time.Second, func() bool {
		s := rec.snapshot()
		return len(s) == 2
	}) {
		t.Fatalf("hot reload did not propagate v2; last=%+v", rec.snapshot())
	}
}

// TestWatcherMalformedFileKeepsPreviousState pins the fail-soft
// contract: a parse failure must NOT clear the in-memory whitelist.
// The previously applied state stays in effect until the operator
// fixes the file.
func TestWatcherMalformedFileKeepsPreviousState(t *testing.T) {
	t.Parallel()
	rec := &recordedSet{}
	stop := make(chan struct{})
	defer close(stop)
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.json")

	good := []whitelistFileEntry{{CIDR: "10.128.0.0/9", Rate: 99}}
	if data, _ := json.Marshal(good); os.WriteFile(path, data, 0o644) != nil {
		t.Fatalf("write good")
	}
	go watchRateLimitWhitelist(path, 20*time.Millisecond, rec.set, stop)
	if !waitFor(2*time.Second, func() bool { return rec.callCount() >= 1 }) {
		t.Fatalf("watcher did not pick up initial good file")
	}
	callsAfterGood := rec.callCount()

	// Replace with malformed JSON. Bump mtime so the watcher tries.
	if os.WriteFile(path, []byte("{ not json"), 0o644) != nil {
		t.Fatalf("write bad")
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)

	time.Sleep(150 * time.Millisecond)
	if rec.callCount() > callsAfterGood {
		t.Fatalf("watcher called set on malformed file (calls=%d > %d)",
			rec.callCount(), callsAfterGood)
	}
}
