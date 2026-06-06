// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestHandler is a minimal-cb Handler usable for unit tests.
func newTestHandler() *Handler {
	return NewHandler(Callbacks{
		GetDashboardToken: func() string { return "test-dash" },
		GetAdminToken:     func() string { return "test-admin" },
		BuildStatsPayload: func(bool) map[string]interface{} {
			return map[string]interface{}{"ok": true}
		},
		GetNodes:        func() []NodeSnapshot { return nil },
		RequestCount:    func() int64 { return 0 },
		StartTime:       func() time.Time { return time.Now().Add(-time.Hour) },
		NodeCount:       func() int { return 0 },
		OnlineCount:     func(time.Time) int { return 0 },
		StaleThreshold:  func() time.Duration { return 5 * time.Minute },
		TriggerSnapshot: func() error { return nil },
		UpdateGauges:    func() {},
		WriteMetrics:    func(io.Writer) {},
		ListenerAddr:    func() string { return "" }, // disabled
		BeaconAddr:      func() string { return "" }, // disabled
		ReadyCh: func() <-chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		},
		Done: func() <-chan struct{} { return make(chan struct{}) },
		Save: func() {},
	})
}

func TestNewHandler_Defaults(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if got := h.MaintenanceBanner(); got != "" {
		t.Errorf("initial banner = %q, want empty", got)
	}
	if got := h.GetProbeStates(); got != nil {
		t.Errorf("initial probe states = %v, want nil", got)
	}
}

func TestSetMaintenanceBanner_NoPersistence(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	h.SetMaintenanceBanner("maintenance window 14:00-15:00")
	if got := h.MaintenanceBanner(); got != "maintenance window 14:00-15:00" {
		t.Errorf("got %q", got)
	}
	h.SetMaintenanceBanner("")
	if got := h.MaintenanceBanner(); got != "" {
		t.Errorf("after clear: got %q", got)
	}
}

func TestSetMaintenanceBanner_PersistsToDisk(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	dir := t.TempDir()
	path := filepath.Join(dir, "banner.txt")
	h.SetBannerPath(path)
	h.SetMaintenanceBanner("scheduled outage")

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "scheduled outage" {
		t.Errorf("got %q", body)
	}
}

func TestSetBannerPath_LoadsExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "banner.txt")
	if err := os.WriteFile(path, []byte("pre-existing notice\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	h := newTestHandler()
	h.SetBannerPath(path)
	if got := h.MaintenanceBanner(); got != "pre-existing notice" {
		t.Errorf("got %q (CRLF should be trimmed)", got)
	}
}

func TestSetHTTPProbeAddr_Roundtrip(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	h.SetHTTPProbeAddr(":3000")
	// Probe with empty addr returns false; with set addr, the probe
	// dials a port that won't answer — false too, but exercises the
	// "[0] == ':' rewrite to 127.0.0.1" branch.
	if h.probeHTTP("/anything") {
		t.Error("probeHTTP against non-listening addr: want false")
	}
}

func TestRunProbe_TracksDowntime(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	// 1st: down → CurrentDownStart non-zero.
	h.runProbe("test-probe", false)
	states := h.GetProbeStates()
	if states["test-probe"].CurrentDownStart == 0 {
		t.Error("CurrentDownStart should be non-zero on first down")
	}
	// 2nd: still down (CurrentDownStart unchanged).
	first := states["test-probe"].CurrentDownStart
	h.runProbe("test-probe", false)
	states = h.GetProbeStates()
	if states["test-probe"].CurrentDownStart != first {
		t.Error("CurrentDownStart should not change while still down")
	}
	// 3rd: up → records downtime interval, clears CurrentDownStart.
	h.runProbe("test-probe", true)
	states = h.GetProbeStates()
	if states["test-probe"].CurrentDownStart != 0 {
		t.Error("CurrentDownStart should reset to 0 on up")
	}
	if len(states["test-probe"].DowntimeIntervals) != 1 {
		t.Errorf("expected 1 downtime interval, got %d", len(states["test-probe"].DowntimeIntervals))
	}
	if states["test-probe"].LastSuccess == 0 {
		t.Error("LastSuccess should be non-zero")
	}
}

func TestSetProbeStates_AndGetSnapshotIsACopy(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	state := &ProbeState{LastSuccess: 12345, DowntimeIntervals: [][2]int64{{1, 2}}}
	h.SetProbeStates(map[string]*ProbeState{"x": state})

	got := h.GetProbeStates()
	if got["x"].LastSuccess != 12345 {
		t.Errorf("got %d", got["x"].LastSuccess)
	}
	// Mutate the snapshot; the internal state must stay intact.
	got["x"].DowntimeIntervals[0][0] = 999
	got2 := h.GetProbeStates()
	if got2["x"].DowntimeIntervals[0][0] == 999 {
		t.Error("snapshot is not a deep copy")
	}
}

func TestProbeRegistry_EmptyAddrFalse(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	// Callbacks.ListenerAddr returns "" by default.
	if h.probeRegistry() {
		t.Error("probeRegistry with empty addr: want false")
	}
}

func TestProbeBeacon_EmptyAddrFalse(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	if h.probeBeacon() {
		t.Error("probeBeacon with empty addr: want false")
	}
}

func TestProbeBeacon_BadResolveFalse(t *testing.T) {
	t.Parallel()
	h := NewHandler(Callbacks{
		BeaconAddr: func() string { return "not a valid host:port" },
	})
	if h.probeBeacon() {
		t.Error("probeBeacon with unresolvable addr: want false")
	}
}

func TestProbeHTTP_EmptyAddrFalse(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	if h.probeHTTP("/api/stats") {
		t.Error("probeHTTP with empty addr: want false")
	}
}

func TestProbeHTTP_HappyPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	h := newTestHandler()
	h.SetHTTPProbeAddr(addr)
	if !h.probeHTTP("/anything") {
		t.Error("probeHTTP against live server: want true")
	}
}

func TestReadSmallBody_NilBodyEmpty(t *testing.T) {
	t.Parallel()
	r := &http.Request{}
	got, err := readSmallBody(r, 100)
	if err != nil || got != "" {
		t.Errorf("nil body: got (%q, %v)", got, err)
	}
}

func TestReadSmallBody_HappyAndTooLarge(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("hello\n  ")))
	got, err := readSmallBody(r, 100)
	if err != nil || got != "hello" {
		t.Errorf("happy: got (%q, %v)", got, err)
	}

	r = httptest.NewRequest("POST", "/", bytes.NewReader([]byte(strings.Repeat("x", 200))))
	if _, err := readSmallBody(r, 100); err == nil {
		t.Error("expected too-large error")
	}
}

func TestLocalhostOnly_AllowsLoopback(t *testing.T) {
	t.Parallel()
	called := false
	h := localhostOnly(func(http.ResponseWriter, *http.Request) { called = true })
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	rw := httptest.NewRecorder()
	h(rw, r)
	if !called {
		t.Error("loopback request should pass through")
	}
}

func TestLocalhostOnly_RejectsRemote(t *testing.T) {
	t.Parallel()
	called := false
	h := localhostOnly(func(http.ResponseWriter, *http.Request) { called = true })
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:80"
	rw := httptest.NewRecorder()
	h(rw, r)
	if called {
		t.Error("remote request should be blocked")
	}
	if rw.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rw.Code)
	}
}

func TestLocalhostOnly_IgnoresXRealIPFromLocalhost(t *testing.T) {
	t.Parallel()
	// When the direct connection is localhost, the middleware must allow
	// regardless of X-Real-IP header (which may be spoofed by a remote
	// attacker through a reverse proxy on the same host).
	called := false
	h := localhostOnly(func(http.ResponseWriter, *http.Request) { called = true })
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Real-IP", "8.8.8.8")
	rw := httptest.NewRecorder()
	h(rw, r)
	if !called {
		t.Error("X-Real-IP should be ignored; loopback request should pass")
	}
}

func TestGetPulseSamples_Empty(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	if got := h.GetPulseSamples(); len(got) != 0 {
		t.Errorf("fresh handler: got %v, want empty", got)
	}
}
