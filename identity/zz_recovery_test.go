// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
	pilotcrypto "github.com/pilot-protocol/common/crypto"
)

func recoveryTestStore(t *testing.T) (*Store, *pilotcrypto.Identity, uint32, *fakeNodeView, *[]string) {
	t.Helper()
	const nodeID uint32 = 0x1ABCD
	id, err := pilotcrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{nodeID: {pubKey: id.PublicKey}}}
	var audits []string
	st := NewStore(fv, Callbacks{
		Save:         func() {},
		Audit:        func(a string, _ ...any) { audits = append(audits, a) },
		OnKeyRotated: func(uint32, string, string) {},
		RecordWAL:    func(uint32, string, string, bool) {},
	})
	return st, id, nodeID, fv, &audits
}

func sigFor(id *pilotcrypto.Identity, challenge string) string {
	return base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge)))
}

func TestHandleSubmitBadge(t *testing.T) {
	st, id, nodeID, fv, _ := recoveryTestStore(t)
	const badge = "pilotbadge:v1:109517:github:1700000000:0:bdg-v1:"
	st.verifyBadge = func(b, sig string, nid uint32) (badgeverify.Badge, error) {
		return badgeverify.Badge{NodeID: nid, Provider: "github"}, nil
	}
	sig := sigFor(id, "submit_badge:"+fmt.Sprint(nodeID)+":"+badge)

	resp, err := st.HandleSubmitBadge(map[string]interface{}{
		"node_id": nodeID, "badge": badge, "badge_sig": "bsig", "signature": sig,
	})
	if err != nil {
		t.Fatalf("submit_badge: %v", err)
	}
	if resp["provider"] != "github" {
		t.Fatalf("resp = %+v", resp)
	}
	if fv.nodes[nodeID].badge != badge || fv.nodes[nodeID].provider != "github" {
		t.Fatalf("badge not stored: %+v", fv.nodes[nodeID])
	}
}

func TestHandleSubmitBadgeRejectsBadNodeSig(t *testing.T) {
	st, _, nodeID, _, _ := recoveryTestStore(t)
	st.verifyBadge = func(b, sig string, nid uint32) (badgeverify.Badge, error) {
		return badgeverify.Badge{NodeID: nid, Provider: "github"}, nil
	}
	_, err := st.HandleSubmitBadge(map[string]interface{}{
		"node_id": nodeID, "badge": "b", "badge_sig": "s", "signature": base64.StdEncoding.EncodeToString([]byte("not-a-real-sig-not-a-real-sig-aa")),
	})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestHandleEnrollRecovery(t *testing.T) {
	st, id, nodeID, fv, audits := recoveryTestStore(t)
	st.verifyEnrollment = func(s, sig string) (badgeverify.Enrollment, error) {
		return badgeverify.Enrollment{NodeID: nodeID, Provider: "github", Commitment: "COMMIT=="}, nil
	}
	sig := sigFor(id, "enroll_recovery:"+fmt.Sprint(nodeID)+":COMMIT==")

	_, err := st.HandleEnrollRecovery(map[string]interface{}{
		"node_id": nodeID, "enrollment": "stmt", "enrollment_sig": "esig", "signature": sig,
	})
	if err != nil {
		t.Fatalf("enroll_recovery: %v", err)
	}
	if fv.nodes[nodeID].recCommit != "COMMIT==" {
		t.Fatalf("commitment not stored: %+v", fv.nodes[nodeID])
	}
	if !contains(*audits, "identity.recovery_enrolled") {
		t.Fatalf("missing audit: %v", *audits)
	}
}

func TestHandleEnrollRecoveryRejectsNodeMismatch(t *testing.T) {
	st, id, nodeID, _, _ := recoveryTestStore(t)
	st.verifyEnrollment = func(s, sig string) (badgeverify.Enrollment, error) {
		return badgeverify.Enrollment{NodeID: 0x99999, Provider: "github", Commitment: "C"}, nil
	}
	sig := sigFor(id, "enroll_recovery:"+fmt.Sprint(nodeID)+":C")
	_, err := st.HandleEnrollRecovery(map[string]interface{}{
		"node_id": nodeID, "enrollment": "s", "enrollment_sig": "e", "signature": sig,
	})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected node_id mismatch, got %v", err)
	}
}

func recoverMsg(t *testing.T, nodeID uint32) (map[string]interface{}, string) {
	t.Helper()
	newID, _ := pilotcrypto.GenerateIdentity()
	newPubB64 := pilotcrypto.EncodePublicKey(newID.PublicKey)
	return map[string]interface{}{
		"node_id": nodeID, "recovery": "stmt", "recovery_sig": "rsig", "new_public_key": newPubB64,
	}, newPubB64
}

func TestHandleRecoverIdentity(t *testing.T) {
	st, _, nodeID, fv, audits := recoveryTestStore(t)
	// Enrolled commitment on the node.
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")

	msg, newPubB64 := recoverMsg(t, nodeID)
	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{
			NodeID: nodeID, NewPubKey: newPubB64, Commitment: "COMMIT==",
			Exp: time.Now().Add(5 * time.Minute).Unix(), Nonce: "nonce-1", Kid: "rec-v1",
		}, nil
	}

	resp, err := st.HandleRecoverIdentity(msg)
	if err != nil {
		t.Fatalf("recover_identity: %v", err)
	}
	if resp["public_key"] != newPubB64 {
		t.Fatalf("resp = %+v", resp)
	}
	// Key was force-rotated to the new key.
	gotKey, _ := fv.LookupNodeKey(nodeID)
	if pilotcrypto.EncodePublicKey(gotKey) != newPubB64 {
		t.Fatal("key was not force-rotated to the new key")
	}
	if !contains(*audits, "node.recovered") {
		t.Fatalf("missing node.recovered notification: %v", *audits)
	}
}

func TestHandleRecoverIdentityRejectsCommitmentMismatch(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "ENROLLED==", "github")
	msg, newPubB64 := recoverMsg(t, nodeID)
	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{NodeID: nodeID, NewPubKey: newPubB64, Commitment: "DIFFERENT==", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n"}, nil
	}
	_, err := st.HandleRecoverIdentity(msg)
	if err == nil || !strings.Contains(err.Error(), "does not match the enrolled") {
		t.Fatalf("expected commitment mismatch, got %v", err)
	}
}

func TestHandleRecoverIdentityRejectsNonceReplay(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")
	msg, newPubB64 := recoverMsg(t, nodeID)
	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{NodeID: nodeID, NewPubKey: newPubB64, Commitment: "COMMIT==", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "reused"}, nil
	}
	if _, err := st.HandleRecoverIdentity(msg); err != nil {
		t.Fatalf("first recovery should succeed: %v", err)
	}
	// Replay the same nonce.
	msg2, _ := recoverMsg(t, nodeID)
	msg2["new_public_key"] = newPubB64
	if _, err := st.HandleRecoverIdentity(msg2); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected nonce-replay rejection, got %v", err)
	}
}

// TestHandleRecoverIdentityRejectsNonceReplayAcrossReload asserts the M1 fix:
// a redeemed nonce must still be rejected after a registry restart / standby
// failover, when the in-memory single-use ledger has been lost. The fakeNodeView
// (which models the persisted+replicated per-node state) carries the consumed
// nonce across the reload, and the per-node ConsumeRecoveryNonce check catches
// the replay even though a brand-new Store has an empty in-memory ledger.
func TestHandleRecoverIdentityRejectsNonceReplayAcrossReload(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")
	msg, newPubB64 := recoverMsg(t, nodeID)
	verify := func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{NodeID: nodeID, NewPubKey: newPubB64, Commitment: "COMMIT==", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "persist-me"}, nil
	}
	st.verifyRecovery = verify
	if _, err := st.HandleRecoverIdentity(msg); err != nil {
		t.Fatalf("first recovery should succeed: %v", err)
	}
	// The persisted per-node state must now carry the consumed nonce.
	if fv.nodes[nodeID].recNonce != "persist-me" {
		t.Fatalf("consumed nonce not persisted on node: %+v", fv.nodes[nodeID])
	}

	// Simulate a restart/failover: a FRESH Store with an empty in-memory
	// ledger, reconstructed over the SAME persisted node state (fv).
	reloaded := NewStore(fv, Callbacks{
		Save:         func() {},
		Audit:        func(string, ...any) {},
		OnKeyRotated: func(uint32, string, string) {},
		RecordWAL:    func(uint32, string, string, bool) {},
	})
	reloaded.verifyRecovery = verify
	// Re-bind the recovery to the node's current (rotated) key so we get past
	// the new-key check and reach the nonce check.
	msg2, newPubB64b := recoverMsg(t, nodeID)
	reloaded.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{NodeID: nodeID, NewPubKey: newPubB64b, Commitment: "COMMIT==", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "persist-me"}, nil
	}
	if _, err := reloaded.HandleRecoverIdentity(msg2); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected nonce replay rejected after reload, got %v", err)
	}
}

func TestHandleRecoverIdentityRejectsUnboundNewKey(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")
	msg, _ := recoverMsg(t, nodeID)
	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		// Recovery authorizes a DIFFERENT new key than the request.
		return badgeverify.Recovery{NodeID: nodeID, NewPubKey: "some-other-key", Commitment: "COMMIT==", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n"}, nil
	}
	if _, err := st.HandleRecoverIdentity(msg); err == nil || !strings.Contains(err.Error(), "not bound to this new key") {
		t.Fatalf("expected new-key binding rejection, got %v", err)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
