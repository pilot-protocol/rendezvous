// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
)

// TestHandleRecoverIdentityRejectsExpiryBeyondWindow pins the bound on the
// recovery-authorization lifetime. The single-use nonce ledger is in-memory,
// so a far-future Exp would let a captured, already-redeemed authorization be
// replayed after a registry restart (which resets the in-memory ledger). The
// handler therefore rejects any statement whose Exp is more than
// maxRecoveryWindow (30m) in the future, BEFORE consuming the nonce or
// touching the binding.
func TestHandleRecoverIdentityRejectsExpiryBeyondWindow(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")
	msg, newPubB64 := recoverMsg(t, nodeID)

	origKey, _ := fv.LookupNodeKey(nodeID)
	origKeyStr := string(origKey)

	// Exp is 31 minutes out — just past the 30-minute window.
	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{
			NodeID: nodeID, NewPubKey: newPubB64, Commitment: "COMMIT==",
			Exp:   time.Now().Add(fuzzMaxRecoveryWindow + time.Minute).Unix(),
			Nonce: "long-lived-nonce",
		}, nil
	}

	_, err := st.HandleRecoverIdentity(msg)
	if err == nil || !strings.Contains(err.Error(), "expiry too far") {
		t.Fatalf("expected expiry-too-far rejection, got %v", err)
	}

	// Rejection must happen before any state change: key unchanged AND the
	// nonce must NOT have been consumed (so a later, in-window authorization
	// reusing the same nonce value is still evaluated on its own merits).
	if got, _ := fv.LookupNodeKey(nodeID); string(got) != origKeyStr {
		t.Fatal("binding mutated despite expiry rejection")
	}
	if fv.nodes[nodeID].recNonce == "long-lived-nonce" {
		t.Fatal("nonce consumed despite expiry rejection (should reject before consuming)")
	}
}

// TestHandleRecoverIdentityAcceptsExpiryAtWindowEdge is the positive control:
// an Exp safely inside the window (well under 30m) is accepted, proving the
// bound rejects only over-long lifetimes rather than blocking legitimate
// minutes-valid recoveries.
func TestHandleRecoverIdentityAcceptsExpiryAtWindowEdge(t *testing.T) {
	st, _, nodeID, fv, _ := recoveryTestStore(t)
	fv.SetRecoveryEnrollment(nodeID, "COMMIT==", "github")
	msg, newPubB64 := recoverMsg(t, nodeID)

	st.verifyRecovery = func(s, sig string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{
			NodeID: nodeID, NewPubKey: newPubB64, Commitment: "COMMIT==",
			Exp:   time.Now().Add(fuzzMaxRecoveryWindow - time.Minute).Unix(),
			Nonce: "in-window-nonce",
		}, nil
	}

	if _, err := st.HandleRecoverIdentity(msg); err != nil {
		t.Fatalf("recovery just inside the window must succeed, got %v", err)
	}
}
