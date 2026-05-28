// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"testing"
	"time"
)

// expiryOKView lets the SetKeyExpiry tests succeed end-to-end with an
// enterprise node + working UpdateNodeKeyExpiry.
type expiryOKView struct {
	*adminCheckingView
	storedPubKey  []byte
	currentExpiry time.Time
	enterprise    bool
}

func (v *expiryOKView) LookupNodeKey(uint32) ([]byte, bool) {
	return v.storedPubKey, v.storedPubKey != nil
}
func (v *expiryOKView) NodeIsEnterprise(uint32) bool { return v.enterprise }
func (v *expiryOKView) UpdateNodeKeyExpiry(_ uint32, exp time.Time) (time.Time, bool) {
	old := v.currentExpiry
	v.currentExpiry = exp
	return old, true
}

func newExpiryView(nodes map[uint32]fakeNode, enterprise bool) *expiryOKView {
	return &expiryOKView{
		adminCheckingView: &adminCheckingView{
			fakeNodeView: &fakeNodeView{nodes: nodes},
			adminOK:      true,
		},
		storedPubKey: []byte("pk"),
		enterprise:   enterprise,
	}
}

func TestHandleSetKeyExpiry_NonEnterpriseRejected(t *testing.T) {
	t.Parallel()
	view := newExpiryView(map[uint32]fakeNode{1: {}}, false)
	st := NewStore(view, Callbacks{Save: func() {}, Audit: func(string, ...any) {}})
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err == nil {
		t.Error("expected enterprise-required error")
	}
}

func TestHandleSetKeyExpiry_SetHappyPath(t *testing.T) {
	t.Parallel()
	view := newExpiryView(map[uint32]fakeNode{1: {}}, true)
	st := NewStore(view, Callbacks{Save: func() {}, Audit: func(string, ...any) {}})
	exp := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	resp, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": exp,
	})
	if err != nil {
		t.Fatalf("HandleSetKeyExpiry: %v", err)
	}
	if resp["expires_at"] != exp {
		t.Errorf("expires_at = %v, want %s", resp["expires_at"], exp)
	}
}

func TestHandleSetKeyExpiry_ClearHappyPath(t *testing.T) {
	t.Parallel()
	view := newExpiryView(map[uint32]fakeNode{1: {}}, true)
	view.currentExpiry = time.Now().Add(time.Hour)
	st := NewStore(view, Callbacks{Save: func() {}, Audit: func(string, ...any) {}})
	resp, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": "never",
	})
	if err != nil {
		t.Fatalf("HandleSetKeyExpiry: %v", err)
	}
	if _, hasExp := resp["expires_at"]; hasExp {
		t.Errorf("expires_at should NOT be in clear response: %v", resp)
	}
}

func TestHandleSetKeyExpiry_ClearWithoutPriorExpiry(t *testing.T) {
	t.Parallel()
	view := newExpiryView(map[uint32]fakeNode{1: {}}, true)
	// currentExpiry stays zero
	st := NewStore(view, Callbacks{Save: func() {}, Audit: func(string, ...any) {}})
	_, err := st.HandleSetKeyExpiry(map[string]interface{}{
		"node_id":    float64(1),
		"expires_at": "",
	})
	if err != nil {
		t.Errorf("clear without prior: %v", err)
	}
}
