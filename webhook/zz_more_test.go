// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStore_SetInitialBackoff_NoOpWithoutDispatcher(t *testing.T) {
	t.Parallel()
	st := NewStore()
	// SetInitialBackoff without a dispatcher is a no-op (no panic).
	st.SetInitialBackoff(50 * time.Millisecond)
}

func TestStore_SetInitialBackoff_AppliesToDispatcher(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	st := NewStore()
	st.SetURL(srv.URL)
	t.Cleanup(func() { st.SetURL("") })

	st.SetInitialBackoff(50 * time.Millisecond)
	// Verify the dispatcher's backoff is the one we set.
	st.mu.RLock()
	got := st.disp.initialBackoff
	st.mu.RUnlock()
	if got != 50*time.Millisecond {
		t.Errorf("initialBackoff = %v, want 50ms", got)
	}
}

func TestDispatcher_NilSafe(t *testing.T) {
	t.Parallel()
	var d *dispatcher
	d.Emit("act", nil)
	d.Close()
	if got := d.getDLQ(); got != nil {
		t.Errorf("nil.getDLQ = %v", got)
	}
	a, b, c := d.stats()
	if a != 0 || b != 0 || c != 0 {
		t.Errorf("nil.stats = (%d, %d, %d), want all 0", a, b, c)
	}
}

func TestDispatcher_EmitDropsWhenQueueFull(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second) // hold up so queue fills
	}))
	defer srv.Close()
	d := newDispatcher(srv.URL)
	t.Cleanup(d.Close)

	// Pump many events fast.
	for i := 0; i < 5000; i++ {
		d.Emit("flood", nil)
	}
	// Some should have dropped — but the count is heuristic, we only
	// verify no panic + counter is reachable.
	_, _, dropped := d.stats()
	_ = dropped
}

func TestDispatcher_CloseDrainsBufferedEvents(t *testing.T) {
	t.Parallel()
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen.Add(1)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	d := newDispatcher(srv.URL)

	// Queue 3 events then Close — Close should drain them.
	d.Emit("a", nil)
	d.Emit("b", nil)
	d.Emit("c", nil)
	d.Close()

	// At least one delivered (drain ran the loop).
	if seen.Load() == 0 {
		t.Error("Close did not drain queued events")
	}
}

func TestDispatcher_Post4xxAddsToDLQ(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400) // client error → no retry
	}))
	defer srv.Close()
	d := newDispatcher(srv.URL)
	d.initialBackoff = 10 * time.Millisecond
	t.Cleanup(d.Close)

	d.Emit("client-err", nil)
	// Wait for the dispatcher to process.
	for i := 0; i < 50; i++ {
		_, failed, _ := d.stats()
		if failed > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := d.getDLQ(); len(got) == 0 {
		t.Errorf("DLQ should have 1 entry after 4xx, got %d", len(got))
	}
}

func TestDispatcher_AddToDLQ_DropsOldestWhenFull(t *testing.T) {
	t.Parallel()
	d := newDispatcher("http://placeholder.invalid")
	t.Cleanup(d.Close)
	d.dlqMu.Lock()
	d.dlqMax = 2
	d.dlqMu.Unlock()

	for i := 0; i < 5; i++ {
		d.addToDLQ(&Event{EventID: uint64(i)})
	}
	got := d.getDLQ()
	if len(got) != 2 {
		t.Errorf("DLQ len = %d, want 2 (cap)", len(got))
	}
	if got[0].EventID != 3 || got[1].EventID != 4 {
		t.Errorf("DLQ contents = %v, want oldest dropped", got)
	}
}

func TestDispatcher_EmitAfterCloseIsNoop(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	d := newDispatcher(srv.URL)
	d.Close()
	d.Emit("after-close", nil)
	// Just verify no panic.
}

// TestDispatcher_RaceyCloseEmit ensures concurrent Emit+Close doesn't panic.
// TestStore_SetSecret_SignsWebhook verifies that when a secret is set,
// outbound webhook POSTs carry an X-Pilot-Signature-256 header with the
// hex-encoded HMAC-SHA256 of the request body (PILOT-239).
func TestStore_SetSecret_SignsWebhook(t *testing.T) {
	t.Parallel()
	secret := "test-secret-pilot"
	var (
		mu         sync.Mutex
		sigHeader  string
		bodyBytes  []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sigHeader = r.Header.Get("X-Pilot-Signature-256")
		bodyBytes, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	st := NewStore()
	defer st.Close()
	st.SetInitialBackoff(time.Millisecond)
	st.SetURL(srv.URL)
	st.SetSecret(secret)

	st.Emit("test.secret", map[string]interface{}{"k": "v"})

	getSig := func() string { mu.Lock(); defer mu.Unlock(); return sigHeader }
	getBody := func() []byte { mu.Lock(); defer mu.Unlock(); return bodyBytes }

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if getSig() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	gotSig := getSig()
	if gotSig == "" {
		t.Fatal("X-Pilot-Signature-256 header not set when secret is configured")
	}

	// Verify the HMAC ourselves.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(getBody())
	expected := hex.EncodeToString(mac.Sum(nil))
	if gotSig != expected {
		t.Fatalf("HMAC mismatch: got %s, want %s", gotSig, expected)
	}
}

// TestStore_SetSecret_NoSignatureWhenNoSecret verifies that no signature
// header is added when the secret is empty (backward-compatible).
func TestStore_SetSecret_NoSignatureWhenNoSecret(t *testing.T) {
	t.Parallel()
	var (
		mu        sync.Mutex
		sigHeader string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sigHeader = r.Header.Get("X-Pilot-Signature-256")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	st := NewStore()
	defer st.Close()
	st.SetInitialBackoff(time.Millisecond)
	st.SetURL(srv.URL)
	// Do NOT call SetSecret — default is empty.

	st.Emit("test.nosecret", map[string]interface{}{"k": "v"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, delivered, _ := st.disp.stats()
		if delivered > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := sigHeader
	mu.Unlock()
	if got != "" {
		t.Fatal("X-Pilot-Signature-256 should NOT be set when no secret configured")
	}
}

func TestDispatcher_RaceyCloseEmit(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	d := newDispatcher(srv.URL)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			d.Emit("race", nil)
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		d.Close()
	}()
	wg.Wait()
}
