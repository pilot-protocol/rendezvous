// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"errors"
	"testing"
)

func TestHandleRegister_RequiresPublicKey(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleRegister(map[string]interface{}{
		"owner": "alice",
	}, "10.0.0.1:4000", nil, nil)
	if err == nil {
		t.Error("expected error for missing public_key")
	}
}

func TestHandleRegister_VerifyTokenError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)
	_, err := st.HandleRegister(map[string]interface{}{
		"public_key":     pubKey,
		"identity_token": "bad-token",
	}, "10.0.0.1:4000",
		func(string) (string, error) { return "", errors.New("verify failed") },
		nil,
	)
	if err == nil {
		t.Error("expected verify error")
	}
}

func TestHandleRegister_WithVerifyTokenAndSetExternalID(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)
	var setNodeID uint32
	var setExtID string
	resp, err := st.HandleRegister(map[string]interface{}{
		"public_key":     pubKey,
		"identity_token": "ok",
		"owner":          "alice",
	}, "10.0.0.1:4000",
		func(string) (string, error) { return "ext-alice", nil },
		func(nid uint32, ext string) { setNodeID = nid; setExtID = ext },
	)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	if resp["external_id"] != "ext-alice" {
		t.Errorf("external_id = %v", resp["external_id"])
	}
	if setExtID != "ext-alice" || setNodeID == 0 {
		t.Errorf("setExternalID got (%d, %q)", setNodeID, setExtID)
	}
}

func TestHandleRegister_LANAddrsAndNewerProtocolWarning(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)
	resp, err := st.HandleRegister(map[string]interface{}{
		"public_key":       pubKey,
		"owner":            "alice",
		"lan_addrs":        []interface{}{"192.168.1.5:4000", "192.168.1.6:4000"},
		"protocol_version": float64(9999),
		"relay_only":       true,
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	if resp["observed_addr"] == nil {
		t.Error("observed_addr should be set")
	}
}

func TestHandleRegister_InvalidHostnameStillRegisters(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)
	resp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKey,
		"owner":      "alice",
		"hostname":   "BAD!NAME",
	}, "10.0.0.1:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	if _, ok := resp["hostname_error"]; !ok {
		t.Error("expected hostname_error in response")
	}
}

func TestHandleReRegister_InvalidPubKey(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	_, err := st.HandleReRegister("!!!", "10.0.0.1:4000", "alice", "", nil, "1.0.0", false, false)
	if err == nil {
		t.Error("expected invalid-pubkey error")
	}
}

func TestHandleReRegister_ExistingNodeUpdatesFields(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)
	// First register.
	resp1, err := st.HandleReRegister(pubKey, "10.0.0.1:4000", "alice", "host1", []string{"192.168.1.5:4000"}, "1.0.0", false, false)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	nodeID1 := resp1["node_id"].(uint32)

	// Re-register with same pubkey — should return same node_id (fast path).
	resp2, err := st.HandleReRegister(pubKey, "10.0.0.2:4000", "alice", "host2", []string{"192.168.1.6:4000"}, "2.0.0", false, false)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if resp2["node_id"] != nodeID1 {
		t.Errorf("node_id changed: %v != %v", resp2["node_id"], nodeID1)
	}
}
