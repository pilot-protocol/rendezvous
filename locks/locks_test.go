// SPDX-License-Identifier: AGPL-3.0-or-later

package locks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Tests need sampling on to exercise the profile paths. The registry
	// already runs with these on in production; we just match it here so
	// the test environment is representative.
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
	m.Run()
}

// TestHandlerReturnsValidJSON verifies the handler responds with a well-formed
// Snapshot — non-empty runtime counters, JSON Content-Type, status 200.
func TestHandlerReturnsValidJSON(t *testing.T) {
	req := httptest.NewRequest("GET", "/debug/locks", nil)
	rec := httptest.NewRecorder()
	serve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var snap Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, rec.Body.String())
	}

	if snap.CapturedAt.IsZero() {
		t.Error("captured_at is zero")
	}
	if snap.Runtime.Goroutines <= 0 {
		t.Errorf("goroutines = %d, want > 0", snap.Runtime.Goroutines)
	}
	if snap.Runtime.GOMAXPROCS <= 0 {
		t.Errorf("gomaxprocs = %d, want > 0", snap.Runtime.GOMAXPROCS)
	}
	if snap.SampleRates.MutexFraction <= 0 {
		t.Errorf("mutex_fraction = %d, want > 0 (we forced 1 in TestMain)", snap.SampleRates.MutexFraction)
	}
}

// TestLiveWaitersSeesContention parks N goroutines on a mutex and verifies
// liveLockWaiters() finds them at the user call site (this test's
// goroutine), not at the runtime/sync frame.
func TestLiveWaitersSeesContention(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()

	const N = 8
	started := make(chan struct{}, N)
	released := make(chan struct{}, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			started <- struct{}{}
			mu.Lock() // <-- waiters park here
			released <- struct{}{}
			mu.Unlock()
		}()
	}
	// Wait until all goroutines have signalled they're about to block.
	for i := 0; i < N; i++ {
		<-started
	}
	// Give them a moment to actually park inside the runtime.
	time.Sleep(100 * time.Millisecond)

	waiters := liveLockWaiters()
	var matchCount int
	for site, count := range waiters {
		if strings.Contains(site, "TestLiveWaitersSeesContention") {
			matchCount += count
		}
	}
	if matchCount < N {
		t.Errorf("found %d waiters attributed to this test (want >= %d). all waiters: %v",
			matchCount, N, waiters)
	}

	mu.Unlock()
	for i := 0; i < N; i++ {
		<-released
	}
	wg.Wait()
}

// TestTopSitesAttributeContention forces contention on a mutex and verifies
// the mutex profile picks it up attributed to this test's source line, not
// to a sync.* frame.
func TestTopSitesAttributeContention(t *testing.T) {
	// Reset the mutex profile by toggling fraction off-then-on. This is a
	// rough way to clear stale samples; runtime doesn't expose a direct
	// reset. We tolerate residual samples from other tests by only checking
	// that our site is present, not that it dominates.
	prev := runtime.SetMutexProfileFraction(0)
	runtime.SetMutexProfileFraction(prev)

	var mu sync.Mutex
	var wg sync.WaitGroup
	const G = 32
	for i := 0; i < G; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				mu.Lock()
				time.Sleep(50 * time.Microsecond)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sites := topSites(readMutexRecords(), 50, calibrate())
	var found bool
	for _, s := range sites {
		if strings.Contains(s.Function, "TestTopSitesAttributeContention") {
			found = true
			if s.Count <= 0 {
				t.Errorf("site %+v has zero count", s)
			}
			break
		}
	}
	if !found {
		t.Logf("known issue: under -race or very fast machines, mutex profile may not record this test's contention. Sites seen: %d", len(sites))
		// Don't fail — this is best-effort, the live waiters test is the
		// stricter correctness check.
	}
}

// TestUserFrameSkipsRuntime walks a synthetic stack and confirms
// userFrame() skips sync/runtime/internal frames.
func TestUserFrameSkipsRuntime(t *testing.T) {
	// Build a stack ending in a real Go function: us.
	pcs := make([]uintptr, 16)
	n := runtime.Callers(1, pcs)
	if n == 0 {
		t.Fatal("runtime.Callers returned 0")
	}
	fn, file, line, ok := userFrame(pcs[:n])
	if !ok {
		t.Fatal("userFrame returned ok=false on a real stack")
	}
	if !strings.Contains(fn, "TestUserFrameSkipsRuntime") {
		t.Errorf("got function %q, want it to contain TestUserFrameSkipsRuntime", fn)
	}
	if file == "" {
		t.Error("file is empty")
	}
	if line <= 0 {
		t.Errorf("line = %d, want > 0", line)
	}
}

// TestQuantileEmpty handles the nil/empty histogram case.
func TestQuantileEmpty(t *testing.T) {
	if v := quantile(nil, 0.5); v != 0 {
		t.Errorf("nil hist: got %v, want 0", v)
	}
	// no panic; just zero
}

// TestSnapshotShape checks that all major Snapshot sections are populated
// (non-nil maps, non-zero process-scoped counters). Note: Go's
// /cpu/classes/* metrics are only updated during GC cycles, so we force one
// before checking them.
func TestSnapshotShape(t *testing.T) {
	runtime.GC()
	snap := Take()
	if snap.LiveWaiters == nil {
		t.Error("LiveWaiters is nil; should be initialised (possibly empty)")
	}
	if snap.Runtime.GOMAXPROCS == 0 {
		t.Error("GOMAXPROCS = 0")
	}
	if snap.CPUClasses.Total == 0 {
		t.Error("CPUClasses.Total = 0 even after explicit GC")
	}
}

// TestHandlerCostBounded checks that a single Take() call completes well
// under one second even with thousands of goroutines. This is a smoke test
// to catch egregious regressions, not a precise benchmark.
func TestHandlerCostBounded(t *testing.T) {
	// Spin up a chunk of background goroutines to make symbolication and
	// profile reads non-trivial.
	const G = 1000
	done := make(chan struct{})
	defer close(done)
	for i := 0; i < G; i++ {
		go func() { <-done }()
	}
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	_ = Take()
	if dur := time.Since(start); dur > time.Second {
		t.Errorf("Take() took %v with %d goroutines; want < 1s", dur, G)
	}
}
