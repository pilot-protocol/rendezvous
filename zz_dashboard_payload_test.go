// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"
)

// TestBuildDashboardStatsPayload_AuthenticatedHasNetworks exercises the
// authenticated branch of buildDashboardStatsPayload.
func TestBuildDashboardStatsPayload_AuthenticatedAndUnauthenticated(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	// Unauthenticated payload: no per-network table.
	payload := s.buildDashboardStatsPayload(false)
	if _, ok := payload["networks"]; ok {
		t.Error("unauthenticated payload should not expose 'networks'")
	}
	// Always-present keys.
	for _, k := range []string{"total_requests", "total_nodes", "active_nodes", "uptime_secs"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("missing key %q in payload", k)
		}
	}

	// Authenticated payload: same baseline, possibly with networks (empty here).
	payload = s.buildDashboardStatsPayload(true)
	if _, ok := payload["total_requests"]; !ok {
		t.Error("authenticated payload missing total_requests")
	}
}

// TestOnlineCount_FreshServerIsZero covers the loop body when no nodes exist.
func TestOnlineCount_FreshServerIsZero(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.onlineCount(time.Now().Add(-time.Hour)); got != 0 {
		t.Errorf("fresh server: got %d, want 0", got)
	}
}

// TestGetPulseSamples_LegacyStubReturnsNil covers the legacy stub.
func TestGetPulseSamples_LegacyStubReturnsNil(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.GetPulseSamples(); got != nil {
		t.Errorf("legacy stub: got %v, want nil", got)
	}
}

// TestDedupStrTrimRight covers the helper.
func TestDedupStrTrimRight(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"hello\n":         "hello",
		"hello\r\n":       "hello",
		"hello\t\t  ":     "hello",
		"trailing only ":  "trailing only",
		"":                "",
	}
	for in, want := range cases {
		if got := dedupStrTrimRight(in); got != want {
			t.Errorf("dedupStrTrimRight(%q) = %q, want %q", in, got, want)
		}
	}
}
