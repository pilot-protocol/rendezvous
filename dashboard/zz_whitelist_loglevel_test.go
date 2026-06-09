// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mountWhitelistAndLogLevel re-mounts the whitelist + log-level endpoints
// as exact replicas of the Serve() registrations so the focused tests
// don't have to stand up the whole dashboard. Mirrors mountFullOpsHandlers.
func mountWhitelistAndLogLevel(h *Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/admin/whitelist", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if h.cb.WhitelistGet == nil {
				http.Error(w, "not configured", http.StatusNotFound)
				return
			}
			data, err := h.cb.WhitelistGet()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var entries []map[string]any
			parseErr := ""
			if err := json.Unmarshal(data, &entries); err != nil {
				parseErr = err.Error()
				entries = []map[string]any{}
			}
			w.Header().Set("Content-Type", "application/json")
			out := map[string]interface{}{"entries": entries, "count": len(entries)}
			if parseErr != "" {
				out["parse_error"] = parseErr
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPut:
			if h.cb.WhitelistSet == nil {
				http.Error(w, "not configured", http.StatusMethodNotAllowed)
				return
			}
			var asObj struct {
				Entries []map[string]any `json:"entries"`
			}
			body := new(bytes.Buffer)
			_, _ = body.ReadFrom(r.Body)
			raw := body.Bytes()
			var arr []map[string]any
			if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Entries != nil {
				arr = asObj.Entries
			} else if err := json.Unmarshal(raw, &arr); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			canonical, _ := json.MarshalIndent(arr, "", "  ")
			if err := h.cb.WhitelistSet(canonical); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(arr)})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/admin/runtime/log-level", h.requireAdminToken(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			lvl := "unknown"
			if h.cb.GetLogLevel != nil {
				lvl = h.cb.GetLogLevel()
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"level": lvl})
		case http.MethodPut:
			if h.cb.SetLogLevel == nil {
				http.Error(w, "not configured", http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Level string `json:"level"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := h.cb.SetLogLevel(body.Level); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "level": body.Level})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	return mux
}

func whitelistCallbacks(initial string) (Callbacks, *string) {
	state := initial
	cb := minimalCallbacks()
	cb.GetAdminToken  = func() string { return "OPS" }
	cb.WhitelistGet   = func() ([]byte, error) { return []byte(state), nil }
	cb.WhitelistSet   = func(data []byte) error { state = string(data); return nil }
	return cb, &state
}

// GET returns the on-disk JSON parsed into entries[], even when the
// underlying file is the bare-array shape used by the watcher.
func TestWhitelist_GETReturnsEntries(t *testing.T) {
	t.Parallel()
	cb, _ := whitelistCallbacks(`[{"cidr":"10.0.0.0/8","rate":100000}]`)
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/admin/whitelist", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var body struct {
		Count   int              `json:"count"`
		Entries []map[string]any `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != 1 || body.Entries[0]["cidr"] != "10.0.0.0/8" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

// PUT accepting the {entries:[…]} shape writes through to the setter
// callback and re-canonicalises to a bare array on disk.
func TestWhitelist_PUTAcceptsEntriesShape(t *testing.T) {
	t.Parallel()
	cb, state := whitelistCallbacks(`[]`)
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	payload := `{"entries":[{"cidr":"10.0.0.0/8","rate":5000},{"cidr":"172.16.0.0/12","rate":2000}]}`
	req, _ := http.NewRequest("PUT", srv.URL+"/api/admin/whitelist", strings.NewReader(payload))
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(*state, `"cidr": "10.0.0.0/8"`) || !strings.Contains(*state, `"cidr": "172.16.0.0/12"`) {
		t.Fatalf("setter not invoked with new contents; state=%s", *state)
	}
}

// PUT accepting a bare array writes through unchanged.
func TestWhitelist_PUTAcceptsBareArray(t *testing.T) {
	t.Parallel()
	cb, state := whitelistCallbacks(`[]`)
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	payload := `[{"cidr":"203.0.113.0/24","rate":1000}]`
	req, _ := http.NewRequest("PUT", srv.URL+"/api/admin/whitelist", strings.NewReader(payload))
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if !strings.Contains(*state, `"cidr": "203.0.113.0/24"`) {
		t.Fatalf("bare-array PUT not persisted; state=%s", *state)
	}
}

// GET without a configured callback returns 404 — operator sees a clear
// signal that whitelist editing isn't wired (vs. returning empty list).
func TestWhitelist_GETUnconfiguredReturns404(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "OPS" }
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/admin/whitelist", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// PUT log-level with a known level invokes the setter; a bad level returns 400.
func TestLogLevel_PUTAcceptsKnownAndRejectsBad(t *testing.T) {
	t.Parallel()
	var got string
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "OPS" }
	cb.GetLogLevel   = func() string { return "info" }
	cb.SetLogLevel   = func(level string) error {
		switch level {
		case "debug", "info", "warn", "error":
			got = level
			return nil
		}
		return fmt.Errorf("invalid level %q", level)
	}
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	// Happy path.
	req, _ := http.NewRequest("PUT", srv.URL+"/api/admin/runtime/log-level",
		strings.NewReader(`{"level":"debug"}`))
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || got != "debug" {
		t.Fatalf("happy path: status=%d got=%q", resp.StatusCode, got)
	}

	// Bad level → 400, setter wasn't called with a new value.
	req, _ = http.NewRequest("PUT", srv.URL+"/api/admin/runtime/log-level",
		strings.NewReader(`{"level":"verbose"}`))
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT bad: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for bad level, got %d", resp.StatusCode)
	}
	if got != "debug" {
		t.Fatalf("bad-level call should not have mutated state; got=%q", got)
	}
}

// GET log-level reports unknown when the getter callback isn't configured.
func TestLogLevel_GETReturnsUnknownWhenUnconfigured(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "OPS" }
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/admin/runtime/log-level", nil)
	req.Header.Set("X-Admin-Token", "OPS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Level != "unknown" {
		t.Fatalf("expected level=unknown, got %q", body.Level)
	}
}

// Admin token gate applies to both endpoints uniformly.
func TestWhitelistAndLogLevel_RejectMissingToken(t *testing.T) {
	t.Parallel()
	cb, _ := whitelistCallbacks(`[]`)
	cb.GetLogLevel = func() string { return "info" }
	cb.SetLogLevel = func(level string) error { return nil }
	srv := httptest.NewServer(mountWhitelistAndLogLevel(NewHandler(cb)))
	defer srv.Close()

	for _, path := range []string{"/api/admin/whitelist", "/api/admin/runtime/log-level"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("GET %s expected 401, got %d", path, resp.StatusCode)
		}
	}
}
