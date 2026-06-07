// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"

	"github.com/pilot-protocol/rendezvous/breakers"
)

// TestBreakerGate_OpenBreakerRejectsDispatch confirms that when an
// operator opens a breaker for a mapped msgType, handleMessage returns
// an error mentioning the breaker name + operator reason, and the
// underlying handler never runs (no state mutation).
func TestBreakerGate_OpenBreakerRejectsDispatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	// Open registry.register with a reason.
	mgr := s.BreakerManager()
	if mgr == nil {
		t.Fatal("BreakerManager is nil — server not wired")
	}
	mgr.Set("registry.register", breakers.Open, "maintenance window")

	// Hit handleMessage with a register message. The dispatcher should
	// reject *before* the handler runs, so even a structurally invalid
	// payload returns the breaker error (proves the gate is upstream of
	// payload validation).
	_, err := s.handleMessage(map[string]interface{}{
		"type": "register",
	}, "127.0.0.1:1234")
	if err == nil {
		t.Fatal("expected breaker-open error, got nil")
	}
	if !strings.Contains(err.Error(), "registry.register") {
		t.Errorf("error missing breaker name: %v", err)
	}
	if !strings.Contains(err.Error(), "maintenance window") {
		t.Errorf("error missing operator reason: %v", err)
	}
	if !strings.Contains(err.Error(), "service unavailable") {
		t.Errorf("error should signal service-unavailable semantics: %v", err)
	}
}

// TestBreakerGate_ClosedAllowsDispatch confirms the default-closed
// path lets traffic flow normally — a missing breaker entry must not
// block requests.
func TestBreakerGate_ClosedAllowsDispatch(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// No breaker registered for "register" → default-allow.
	_, err := s.handleMessage(map[string]interface{}{
		"type": "register",
	}, "127.0.0.1:1234")
	// We don't care about the specific error from the register
	// handler (the bare msg is invalid) — only that it's NOT the
	// breaker-open path. The breaker error always contains "breaker"
	// and "service unavailable"; legitimate validation errors don't.
	if err != nil && strings.Contains(err.Error(), "breaker") {
		t.Errorf("default-closed path produced breaker error: %v", err)
	}
}

// TestBreakerGate_OneSwitchCoversMultipleTypes pins the design choice
// that read-path msgTypes share registry.resolve. An operator opens
// one switch and all five read endpoints stop responding — this
// rough-grained surface control is the whole point.
func TestBreakerGate_OneSwitchCoversMultipleTypes(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.BreakerManager().Set("registry.resolve", breakers.Open, "load-shed")
	readTypes := []string{"lookup", "resolve", "resolve_hostname", "list_networks", "list_nodes"}
	for _, mt := range readTypes {
		_, err := s.handleMessage(map[string]interface{}{"type": mt}, "127.0.0.1:1234")
		if err == nil || !strings.Contains(err.Error(), "registry.resolve") {
			t.Errorf("type %q: expected registry.resolve breaker error, got %v", mt, err)
		}
	}
}

// TestBreakerGate_UnmappedTypesIgnoreBreakers makes sure typed an
// unrelated breaker name in breakers.json never gates a handler we
// didn't intend. A mistyped breaker name would otherwise silently
// surface as "all read paths open" which is the opposite of the safety
// goal.
func TestBreakerGate_UnmappedTypesIgnoreBreakers(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// Operator typos a name that no msgType maps to.
	s.BreakerManager().Set("registry.RESOLVES", breakers.Open, "typo")
	for _, mt := range []string{"resolve", "lookup", "list_nodes"} {
		_, err := s.handleMessage(map[string]interface{}{"type": mt}, "127.0.0.1:1234")
		if err != nil && strings.Contains(err.Error(), "breaker") {
			t.Errorf("type %q: typo'd breaker accidentally gated this path: %v", mt, err)
		}
	}
}

// TestBreakerForType_GoldenList pins the full mapping between
// msgType and breaker name. Adding or renaming a mapping is a
// deliberate operator-facing surface change — this test forces a
// reviewer to update the golden list, so silent drift can't reach
// production unnoticed.
func TestBreakerForType_GoldenList(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"register":          "registry.register",
		"heartbeat":         "registry.heartbeat",
		"lookup":            "registry.resolve",
		"resolve":           "registry.resolve",
		"resolve_hostname":  "registry.resolve",
		"list_networks":     "registry.resolve",
		"list_nodes":        "registry.resolve",
		"punch":             "registry.punch",
		"deregister":        "registry.deregister",
		"report_trust":      "registry.trust",
		"revoke_trust":      "registry.trust",
		"check_trust":       "registry.trust",
		"request_handshake": "registry.handshake",
		"poll_handshakes":   "registry.handshake",
		"respond_handshake": "registry.handshake",
		"invite_to_network": "registry.invite",
		"poll_invites":      "registry.invite",
		"respond_invite":    "registry.invite",
		"create_network":    "registry.network_admin",
		"delete_network":    "registry.network_admin",
		"join_network":      "registry.network_admin",
		"leave_network":     "registry.network_admin",
		"rename_network":    "registry.network_admin",
		"beacon_register":   "registry.beacon_register",
		"beacon_list":       "registry.beacon_register",
	}
	if len(want) != len(breakerForType) {
		t.Errorf("size: got %d want %d", len(breakerForType), len(want))
	}
	for k, v := range want {
		if got := breakerForType[k]; got != v {
			t.Errorf("%q: got %q want %q", k, got, v)
		}
	}
	for k, v := range breakerForType {
		if want[k] != v {
			t.Errorf("unexpected mapping %q -> %q in dispatch.go (not in golden)", k, v)
		}
	}
}
