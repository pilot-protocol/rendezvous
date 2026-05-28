// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"testing"
)

// updateOKView is a fakeNodeView wrapper that lets UpdateNodeExternalID
// succeed for known node IDs.
type updateOKView struct {
	*adminCheckingView
	lastOldID    string
	lastNewID    string
	knownNodeIDs map[uint32]bool
}

func (v *updateOKView) UpdateNodeExternalID(id uint32, ext string) (string, bool) {
	if v.knownNodeIDs[id] {
		v.lastNewID = ext
		return v.lastOldID, true
	}
	return "", false
}

func TestHandleSetExternalID_HappyPath(t *testing.T) {
	t.Parallel()
	base := &adminCheckingView{
		fakeNodeView: &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}},
		adminOK:      true,
	}
	view := &updateOKView{
		adminCheckingView: base,
		lastOldID:         "ext-old",
		knownNodeIDs:      map[uint32]bool{1: true},
	}
	st := NewStore(view, Callbacks{
		Save:  func() {},
		Audit: func(string, ...any) {},
	})

	resp, err := st.HandleSetExternalID(map[string]interface{}{
		"node_id":     float64(1),
		"external_id": "ext-new",
	})
	if err != nil {
		t.Fatalf("HandleSetExternalID: %v", err)
	}
	if resp["external_id"] != "ext-new" {
		t.Errorf("external_id = %v, want ext-new", resp["external_id"])
	}
	if view.lastNewID != "ext-new" {
		t.Errorf("view.lastNewID = %q", view.lastNewID)
	}
}
