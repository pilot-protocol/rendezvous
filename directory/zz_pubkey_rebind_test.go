// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// TestReRegister_SameKey_NoRegression asserts the normal refresh/heartbeat
// path is UNCHANGED: re-registering an already-bound owner with the SAME
// public key keeps the same node_id and succeeds without proof. This is the
// path the live production fleet exercises on every heartbeat.
func TestReRegister_SameKey_NoRegression(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	pubKey := genPubKeyB64(t)

	resp1, err := st.HandleReRegister(pubKey, "10.0.0.1:4000", "alice", "host1", nil, "1.0.0", false, false)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	nodeID := resp1["node_id"].(uint32)

	// Same owner, same key, new address — must succeed, same node_id.
	resp2, err := st.HandleReRegister(pubKey, "10.0.0.2:4000", "alice", "host1", nil, "2.0.0", false, false)
	if err != nil {
		t.Fatalf("same-key re-register rejected (regression!): %v", err)
	}
	if resp2["node_id"].(uint32) != nodeID {
		t.Fatalf("node_id changed on same-key re-register: %v != %v", resp2["node_id"], nodeID)
	}
	if resp2["public_key"].(string) != pubKey {
		t.Fatalf("public_key changed on same-key re-register: %v", resp2["public_key"])
	}
}

// TestReRegister_DifferentKey_OwnerReclaim_Rejected asserts the H2/H3 fix:
// an owner-string reclaim that presents a DIFFERENT pubkey for an already-bound
// node_id is refused, and the existing binding (key + badge) is left intact.
func TestReRegister_DifferentKey_OwnerReclaim_Rejected(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)

	origPubKeyB64 := genPubKeyB64(t)
	resp1, err := st.HandleReRegister(origPubKeyB64, "10.0.0.1:4000", "alice", "host1", nil, "1.0.0", false, false)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	nodeID := resp1["node_id"].(uint32)

	// Decorate the node with a verified badge so we can assert it survives.
	origNode := st.nodes[nodeID]
	origKey := append([]byte(nil), origNode.PublicKey...)
	origNode.Badge = "BADGE-DATA"
	origNode.BadgeSig = "BADGE-SIG"
	origNode.VerificationProvider = "github"

	// Attacker re-registers with the SAME owner string but a DIFFERENT key.
	attackerPubKeyB64 := genPubKeyB64(t)
	if attackerPubKeyB64 == origPubKeyB64 {
		t.Fatal("test setup: keys collided")
	}
	_, err = st.HandleReRegister(attackerPubKeyB64, "6.6.6.6:4000", "alice", "host1", nil, "9.9.9", false, false)
	if err == nil {
		t.Fatal("owner-reclaim with a different key must be REJECTED")
	}
	if !strings.Contains(err.Error(), "recover_identity") {
		t.Errorf("rejection should point to recover_identity, got: %v", err)
	}

	// Binding must be unchanged.
	node := st.nodes[nodeID]
	if !bytes.Equal(node.PublicKey, origKey) {
		t.Error("PublicKey was rebound despite rejection")
	}
	attackerKey, _ := crypto.DecodePublicKey(attackerPubKeyB64)
	if bytes.Equal(node.PublicKey, attackerKey) {
		t.Error("node was hijacked to the attacker key")
	}
	// pubKeyIdx must not now point the attacker key at the victim node.
	if got, ok := st.pubKeyIdx[attackerPubKeyB64]; ok {
		t.Errorf("attacker key indexed to node %d", got)
	}
	if got := st.pubKeyIdx[origPubKeyB64]; got != nodeID {
		t.Errorf("original key index lost: pubKeyIdx[orig]=%d want %d", got, nodeID)
	}
	// Badge must be untouched (no stale-badge inheritance).
	if node.Badge != "BADGE-DATA" || node.VerificationProvider != "github" {
		t.Error("badge was disturbed by a rejected rebind")
	}
}

// TestReRegister_ReapedOwnerNode_ReclaimAllowed asserts the legitimate
// restart case: when the owner's node was reaped (no live binding), the same
// owner may reclaim the node_id with a fresh key, and the reclaimed node
// carries NO stale badge.
func TestReRegister_ReapedOwnerNode_ReclaimAllowed(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)

	pubKey := genPubKeyB64(t)
	resp1, err := st.HandleReRegister(pubKey, "10.0.0.1:4000", "alice", "host1", nil, "1.0.0", false, false)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	nodeID := resp1["node_id"].(uint32)

	// Simulate the node being reaped: drop from nodes + pubKeyIdx, keep ownerIdx
	// (this is what ReapStaleNodes / restart leaves behind).
	delete(st.nodes, nodeID)
	delete(st.pubKeyIdx, pubKey)

	newPubKey := genPubKeyB64(t)
	resp2, err := st.HandleReRegister(newPubKey, "10.0.0.9:4000", "alice", "host1", nil, "2.0.0", false, false)
	if err != nil {
		t.Fatalf("reaped-node owner reclaim should succeed: %v", err)
	}
	if resp2["node_id"].(uint32) != nodeID {
		t.Fatalf("reaped reclaim got wrong node_id: %v != %v", resp2["node_id"], nodeID)
	}
	node := st.nodes[nodeID]
	if node.Badge != "" || node.BadgeSig != "" || node.VerificationProvider != "" {
		t.Error("reclaimed reaped node carries a stale badge")
	}
}
