// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"strings"
	"testing"
)

// --- HandleResolveHostname extra branches -------------------------------

func TestHandleResolveHostname_Empty(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleResolveHostname(map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "hostname required") {
		t.Fatalf("%v", err)
	}
}

func TestHandleResolveHostname_NotFound(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleResolveHostname(map[string]interface{}{"hostname": "ghost"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("%v", err)
	}
}

func TestHandleResolveHostname_PublicAllowsAnyone(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[10] = &NodeInfo{ID: 10, Hostname: "pub", Public: true}
	st.hostnameIdx["pub"] = 10
	st.mu.Unlock()
	resp, err := st.HandleResolveHostname(map[string]interface{}{"hostname": "pub"})
	if err != nil {
		t.Fatal(err)
	}
	if resp["public"].(bool) != true || resp["node_id"].(uint32) != 10 {
		t.Fatalf("resp: %+v", resp)
	}
}

func TestHandleResolveHostname_PrivateRequesterIsSelfAllowed(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "self", Public: false}
	st.hostnameIdx["self"] = 42
	st.mu.Unlock()
	resp, err := st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "self",
		"requester_id": float64(42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["node_id"].(uint32) != 42 {
		t.Fatalf("resp: %+v", resp)
	}
}

func TestHandleResolveHostname_PrivateDeniedToStranger(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "priv", Public: false, Networks: []uint16{5}}
	st.nodes[99] = &NodeInfo{ID: 99, Networks: []uint16{6}}
	st.hostnameIdx["priv"] = 42
	st.mu.Unlock()
	_, err := st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "priv",
		"requester_id": float64(99),
	})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestHandleResolveHostname_PrivateAllowedByCommonNetwork(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "priv", Public: false, Networks: []uint16{5, 8}}
	st.nodes[99] = &NodeInfo{ID: 99, Networks: []uint16{7, 8}}
	st.hostnameIdx["priv"] = 42
	st.mu.Unlock()
	resp, err := st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "priv",
		"requester_id": float64(99),
	})
	if err != nil {
		t.Fatalf("expected allowed via shared network 8, got %v", err)
	}
	if resp["node_id"].(uint32) != 42 {
		t.Fatalf("resp: %+v", resp)
	}
}

func TestHandleResolveHostname_PrivateAllowedByTrust(t *testing.T) {
	t.Parallel()
	// Override the IsTrusted callback to return true for any pair.
	st := newTestStore(t)
	st.cb.IsTrusted = func(a, b uint32) bool { return true }
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "priv", Public: false}
	st.nodes[99] = &NodeInfo{ID: 99}
	st.hostnameIdx["priv"] = 42
	st.mu.Unlock()
	resp, err := st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "priv",
		"requester_id": float64(99),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp["node_id"].(uint32) != 42 {
		t.Fatalf("resp: %+v", resp)
	}
}

// --- HandleReRegister fast path -----------------------------------------

func TestHandleReRegister_FastPathRefreshesEndpoint(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	// Register first to populate pubKeyIdx + nodes.
	_, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
		"owner":      "alice",
		"hostname":   "host1",
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatalf("initial register: %v", err)
	}

	// Re-register with same owner + hostname → fast-path endpoint refresh.
	resp, err := st.HandleReRegister(pubKeyB64, "10.0.0.2:4000", "alice", "host1",
		[]string{"192.168.1.5:4000"}, "1.7.2", false, false)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("resp: %+v", resp)
	}
	// Verify endpoint updated.
	st.mu.RLock()
	nodeID := st.pubKeyIdx[pubKeyB64]
	n := st.nodes[nodeID]
	st.mu.RUnlock()
	if n.RealAddr != "10.0.0.2:4000" {
		t.Errorf("RealAddr not refreshed: %q", n.RealAddr)
	}
	if n.Version != "1.7.2" {
		t.Errorf("Version not updated: %q", n.Version)
	}
}

func TestHandleReRegister_SlowPathNewOwner(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	// First register without owner.
	_, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Re-register with new owner triggers slow path.
	resp, err := st.HandleReRegister(pubKeyB64, "10.0.0.2:4000", "newowner", "", nil, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp["type"] != "register_ok" {
		t.Fatalf("%+v", resp)
	}
	st.mu.RLock()
	nodeID := st.pubKeyIdx[pubKeyB64]
	n := st.nodes[nodeID]
	st.mu.RUnlock()
	if n.Owner != "newowner" {
		t.Errorf("Owner = %q", n.Owner)
	}
}

func TestHandleReRegister_BadPubKey(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleReRegister("not-base64!", "10.0.0.1:4000", "", "", nil, "", false, false)
	if err == nil || !strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("%v", err)
	}
}

// --- buildHeartbeatOk ----------------------------------------------------

func TestBuildHeartbeatOk_NoWarning(t *testing.T) {
	t.Parallel()
	b := buildHeartbeatOk(1700000000, false)
	s := string(b)
	if !strings.Contains(s, `"time":1700000000`) {
		t.Errorf("time field missing: %s", s)
	}
	if strings.Contains(s, "key_expiry_warning") {
		t.Errorf("warning should be absent: %s", s)
	}
	if !strings.Contains(s, `"type":"heartbeat_ok"`) {
		t.Errorf("type missing: %s", s)
	}
}

func TestBuildHeartbeatOk_WithWarning(t *testing.T) {
	t.Parallel()
	b := buildHeartbeatOk(42, true)
	s := string(b)
	if !strings.Contains(s, `"key_expiry_warning":true`) {
		t.Errorf("warning missing: %s", s)
	}
	if !strings.Contains(s, `"time":42`) {
		t.Errorf("time missing: %s", s)
	}
}

// --- sanitizeListenAddr (directory pkg, distinct from server's) ---------

func TestSanitizeListenAddr_EmptyClientReturnsRemote(t *testing.T) {
	t.Parallel()
	got := sanitizeListenAddr("1.2.3.4:5", "")
	if got != "1.2.3.4:5" {
		t.Fatalf("got %q", got)
	}
}
