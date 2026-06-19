// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import "testing"

// TestHandleLookupRedactsExternalIDSurfacesBadge proves the privacy fix:
// the unauthenticated lookup never leaks the raw external identity, and
// instead surfaces only the offline-verifiable badge.
func TestHandleLookupRedactsExternalIDSurfacesBadge(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKeyB64 := genPubKeyB64(t)

	regResp, err := st.HandleRegister(map[string]interface{}{
		"public_key": pubKeyB64,
		"owner":      "bob",
	}, "192.168.1.5:4000", nil, nil)
	if err != nil {
		t.Fatalf("HandleRegister: %v", err)
	}
	nodeID := regResp["node_id"].(uint32)

	// A verified node that also carries a raw external identity (kept for
	// RBAC) and a badge.
	node := st.nodes[nodeID]
	node.ExternalID = "github|secret-handle"
	node.Badge = "pilotbadge:v1:1:github:1700000000:0:bdg-v1:"
	node.BadgeSig = "sig"
	node.VerificationProvider = "github"

	resp, err := st.HandleLookup(map[string]interface{}{"node_id": float64(nodeID)})
	if err != nil {
		t.Fatalf("HandleLookup: %v", err)
	}

	if v, leaked := resp["external_id"]; leaked {
		t.Fatalf("lookup must NOT leak external_id, got %v", v)
	}
	if resp["verified"] != true {
		t.Fatalf("lookup should surface verified=true; got %v", resp["verified"])
	}
	if resp["badge"] == nil || resp["badge"] == "" {
		t.Fatalf("lookup should surface the badge; resp=%v", resp)
	}
	if resp["verification_provider"] != "github" {
		t.Fatalf("lookup should surface verification_provider; got %v", resp["verification_provider"])
	}
}
