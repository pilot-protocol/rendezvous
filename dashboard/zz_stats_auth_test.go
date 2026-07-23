// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatsAuth_AdminTokenQueryParam pins the reconciled auth path:
// /api/stats is admin-gated, and the dashboard frontend authenticates
// with admin_token=<token> (the same token it sends to /api/pulse).
// Previously the frontend sent ?token=, which the admin gate ignores,
// so operator stats silently 401'd.
func TestStatsAuth_AdminTokenQueryParam(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "op-secret" }
	// Mark the payload so we can confirm the elevated (authenticated)
	// branch ran.
	cb.BuildStatsPayload = func(authenticated bool) map[string]interface{} {
		return map[string]interface{}{"authenticated": authenticated}
	}
	h := NewHandler(cb)
	srv := httptest.NewServer(h.buildMux())
	defer srv.Close()

	// admin_token query param — what the frontend now sends — is accepted.
	resp, err := http.Get(srv.URL + "/api/stats?admin_token=op-secret")
	if err != nil {
		t.Fatalf("GET /api/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin_token query: status %d, want 200", resp.StatusCode)
	}

	// X-Admin-Token header is accepted too.
	req, _ := http.NewRequest("GET", srv.URL+"/api/stats", nil)
	req.Header.Set("X-Admin-Token", "op-secret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stats (header): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("X-Admin-Token header: status %d, want 200", resp2.StatusCode)
	}
}

// TestStatsAuth_RejectsBadAndMissingToken confirms the gate is not
// weakened: a missing token, a wrong token, and the legacy ?token=
// (which the admin gate does not accept) are all rejected.
func TestStatsAuth_RejectsBadAndMissingToken(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "op-secret" }
	h := NewHandler(cb)
	srv := httptest.NewServer(h.buildMux())
	defer srv.Close()

	cases := []struct {
		name string
		url  string
	}{
		{"missing", srv.URL + "/api/stats"},
		{"wrong admin_token", srv.URL + "/api/stats?admin_token=nope"},
		{"legacy token param not honored by gate", srv.URL + "/api/stats?token=op-secret"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Get(c.url)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s: status %d, want 401", c.name, resp.StatusCode)
			}
		})
	}
}

// TestStatsAuth_UnconfiguredLocksShut confirms that with no admin token
// configured the endpoint is locked shut (matches the PR #50 lockdown).
func TestStatsAuth_UnconfiguredLocksShut(t *testing.T) {
	t.Parallel()
	h := NewHandler(minimalCallbacks()) // GetAdminToken returns ""
	srv := httptest.NewServer(h.buildMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/stats?admin_token=anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unconfigured: status %d, want 401", resp.StatusCode)
	}
}

// TestAdminToken_CSRF_MutationRejectsQueryParam confirms that
// query-param admin_token is REJECTED on mutation endpoints (POST/PUT/...)
// — these require the X-Admin-Token header to prevent CSRF from leaked URLs.
func TestAdminToken_CSRF_MutationRejectsQueryParam(t *testing.T) {
	t.Parallel()
	cb := minimalCallbacks()
	cb.GetAdminToken = func() string { return "op-secret" }
	h := NewHandler(cb)
	srv := httptest.NewServer(h.buildMux())
	defer srv.Close()

	// POST /api/admin/runtime/gc with query-param token — must 401.
	body := bytes.NewBufferString("{}")
	req, _ := http.NewRequest("POST", srv.URL+"/api/admin/runtime/gc?admin_token=op-secret", body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/admin/runtime/gc (query-param): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query-param token on POST got %d, want 401", resp.StatusCode)
	}

	// POST with proper X-Admin-Token header — must succeed.
	req2, _ := http.NewRequest("POST", srv.URL+"/api/admin/runtime/gc", body)
	req2.Header.Set("X-Admin-Token", "op-secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST /api/admin/runtime/gc (header): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("header token on POST got %d, want 200", resp2.StatusCode)
	}
}
