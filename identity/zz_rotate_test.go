// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"strings"
	"testing"
	"time"
)

func TestHandleRotateKey_MissingFields(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	if _, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(1),
		"new_public_key": "AAAA",
	}); err == nil {
		t.Error("missing signature: want error")
	}
	if _, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":   float64(1),
		"signature": "AAAA",
	}); err == nil {
		t.Error("missing new_public_key: want error")
	}
}

func TestHandleRotateKey_BadNewPubKey(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(1),
		"signature":      "AAAA",
		"new_public_key": "!!!", // not valid b64
	})
	if err == nil {
		t.Error("expected bad-key error")
	}
}

func TestHandleRotateKey_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(9999),
		"signature":      "AAAA",
		"new_public_key": "MCowBQYDK2VwAyEABcdefghijklmnopqrstuvwxyz012345678901234ABC=",
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandleSetKeyExpiry_InvalidTime(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{1: {pubKey: []byte("pk")}}, true)
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": "not-a-date",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid expires_at") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetKeyExpiry_PastTimeRejected(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{1: {pubKey: []byte("pk")}}, true)
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	if err == nil || !strings.Contains(err.Error(), "future") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetKeyExpiry_BeyondTenYearsRejected(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{1: {pubKey: []byte("pk")}}, true)
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": time.Now().Add(11 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if err == nil || !strings.Contains(err.Error(), "10 years") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleSetKeyExpiry_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(9999),
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}
