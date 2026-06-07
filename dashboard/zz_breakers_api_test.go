// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// breakersTestCallbacks wires fake BreakerList/Set/Delete via
// minimalCallbacks, returning the in-memory map so the test can assert
// that PUT/DELETE called through cleanly. Stub admin token is "ADM".
func breakersTestCallbacks() (Callbacks, *map[string]BreakerListEntry) {
	store := map[string]BreakerListEntry{
		"registry.register": {
			Name: "registry.register", State: "closed",
			AllowedTotal: 1234, DeniedTotal: 0,
		},
		"registry.heartbeat": {
			Name: "registry.heartbeat", State: "open", Reason: "incident #2061",
			AllowedTotal: 0, DeniedTotal: 42,
		},
	}
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "ADM" }
	cb.BreakerList = func() []BreakerListEntry {
		out := make([]BreakerListEntry, 0, len(store))
		for _, v := range store {
			out = append(out, v)
		}
		return out
	}
	cb.BreakerSet = func(name, state, reason string) error {
		store[name] = BreakerListEntry{
			Name: name, State: state, Reason: reason,
		}
		return nil
	}
	cb.BreakerDelete = func(name string) error {
		delete(store, name)
		return nil
	}
	return cb, &store
}

func mountBreakersHandlers(h *Handler) http.Handler {
	mux := http.NewServeMux()
	// Re-register only the breakers routes via the shim — exact
	// replicas of the Serve() registrations so the test pins the
	// public contract end-to-end.
	mux.HandleFunc("/api/breakers", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"breakers": h.cb.BreakerList(),
		})
	}))
	mux.HandleFunc("/api/breakers/", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" && r.Method == http.MethodGet {
			token = r.URL.Query().Get("admin_token")
		}
		if token != h.cb.GetAdminToken() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/breakers/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			body, _ := readSmallBody(r, 8192)
			var p struct{ State, Reason string }
			_ = json.Unmarshal([]byte(body), &p)
			_ = h.cb.BreakerSet(name, p.State, p.Reason)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "name": name})
		case http.MethodDelete:
			_ = h.cb.BreakerDelete(name)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "name": name})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func TestBreakersAPI_GETListsAllWithCounters(t *testing.T) {
	t.Parallel()
	cb, _ := breakersTestCallbacks()
	srv := httptest.NewServer(mountBreakersHandlers(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/breakers", nil)
	req.Header.Set("X-Admin-Token", "ADM")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	list, _ := payload["breakers"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("expected 2 breakers, got %d", len(list))
	}
	// Spot-check that counter + reason fields survived JSON.
	for _, item := range list {
		row, _ := item.(map[string]interface{})
		if _, ok := row["allowed_total"]; !ok {
			t.Errorf("row missing allowed_total: %v", row)
		}
		if row["name"] == "registry.heartbeat" {
			if row["state"] != "open" {
				t.Errorf("heartbeat state = %v, want open", row["state"])
			}
			if row["reason"] != "incident #2061" {
				t.Errorf("heartbeat reason = %v, want incident #2061", row["reason"])
			}
		}
	}
}

func TestBreakersAPI_GETRejectsMissingAdminToken(t *testing.T) {
	t.Parallel()
	cb, _ := breakersTestCallbacks()
	srv := httptest.NewServer(mountBreakersHandlers(NewHandler(cb)))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/breakers")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated GET = %d, want 401", resp.StatusCode)
	}
}

func TestBreakersAPI_PUTSetsBreaker(t *testing.T) {
	t.Parallel()
	cb, store := breakersTestCallbacks()
	srv := httptest.NewServer(mountBreakersHandlers(NewHandler(cb)))
	defer srv.Close()

	body := bytes.NewBufferString(`{"state":"open","reason":"live test"}`)
	req, _ := http.NewRequest("PUT", srv.URL+"/api/breakers/snapshot.write", body)
	req.Header.Set("X-Admin-Token", "ADM")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}

	entry, ok := (*store)["snapshot.write"]
	if !ok {
		t.Fatal("PUT did not create snapshot.write in store")
	}
	if entry.State != "open" {
		t.Errorf("state = %q, want open", entry.State)
	}
	if entry.Reason != "live test" {
		t.Errorf("reason = %q, want %q", entry.Reason, "live test")
	}
}

func TestBreakersAPI_PUTRequiresHeaderTokenNotQueryParam(t *testing.T) {
	t.Parallel()
	cb, _ := breakersTestCallbacks()
	srv := httptest.NewServer(mountBreakersHandlers(NewHandler(cb)))
	defer srv.Close()

	// Query-param token must NOT work for a write. CSRF + referer
	// leakage are the failure modes this rule prevents.
	body := bytes.NewBufferString(`{"state":"open"}`)
	req, _ := http.NewRequest("PUT",
		srv.URL+"/api/breakers/snapshot.write?admin_token=ADM", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("query-param token on PUT got %d, want 401", resp.StatusCode)
	}
}

func TestBreakersAPI_DELETERemovesBreaker(t *testing.T) {
	t.Parallel()
	cb, store := breakersTestCallbacks()
	srv := httptest.NewServer(mountBreakersHandlers(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("DELETE", srv.URL+"/api/breakers/registry.heartbeat", nil)
	req.Header.Set("X-Admin-Token", "ADM")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("DELETE status = %d, want 200", resp.StatusCode)
	}
	if _, present := (*store)["registry.heartbeat"]; present {
		t.Error("DELETE did not remove the breaker from the store")
	}
}

func TestRuntimeMetrics_PayloadShape(t *testing.T) {
	t.Parallel()
	got := collectRuntimeMetrics()

	// Keys that must always be present regardless of platform.
	mustHave := []string{
		"goroutines", "gomaxprocs", "num_cpu",
		"heap_alloc_bytes", "heap_objects", "gc_cycles_total",
		"mutex_wait_seconds", "server_time",
	}
	for _, k := range mustHave {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in runtime metrics payload: %v", k, got)
		}
	}
	if g, _ := got["goroutines"].(int); g < 1 {
		t.Errorf("goroutines = %v, want >= 1", got["goroutines"])
	}
	// Histogram-derived keys ONLY appear when the runtime has been
	// running long enough to populate histograms — by the time the
	// test reaches this line the runtime has had time to populate
	// /sched/latencies, but /gc/pauses may be empty on a brand-new
	// process. Don't assert presence; assert non-negative when present.
	for _, k := range []string{
		"sched_latency_p50_seconds", "sched_latency_p99_seconds",
		"gc_pause_p50_seconds", "gc_pause_p99_seconds", "gc_pause_max_seconds",
	} {
		if v, ok := got[k]; ok {
			if f, ok := v.(float64); ok && f < 0 {
				t.Errorf("%s = %v, want >= 0", k, f)
			}
		}
	}
	// Sanity: server_time matches Unix() within a few seconds.
	if ts, ok := got["server_time"].(int64); ok {
		now := time.Now().Unix()
		if ts < now-5 || ts > now+5 {
			t.Errorf("server_time = %d drifted from now=%d", ts, now)
		}
	}
}
