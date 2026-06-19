// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"fmt"
	"time"

	pilotcrypto "github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/rendezvous/events"
)

// This file implements the registry side of verified-address badges and
// identity-based recovery. Three protocol commands:
//
//   submit_badge      — node (current key) attaches its verified badge.
//   enroll_recovery   — node (current key) records its recovery commitment.
//   recover_identity  — NO current key: a cold-key-signed recovery
//                       authorization force-rotates the address to a new key.
//
// All three verify issuer/recovery signatures OFFLINE against the pinned
// keyrings in common/badgeverify; the registry never contacts the verifier.

// verifyNodeSig checks that sigB64 is a valid signature by the node's
// CURRENT key over the given challenge — proving the caller controls the
// node. Mirrors HandleRotateKey's phase-2 check.
func (st *Store) verifyNodeSig(nodeID uint32, challenge, sigB64 string) error {
	if sigB64 == "" {
		return fmt.Errorf("missing signature")
	}
	currentPubKey, ok := st.nodes.LookupNodeKey(nodeID)
	if !ok {
		return fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	sig, err := base64Decode(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !pilotcrypto.Verify(currentPubKey, []byte(challenge), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// HandleSubmitBadge implements "submit_badge". The node proves current-key
// ownership, the badge is verified offline against the pinned issuer key
// and bound to this node, and it is stored for lookups to surface.
func (st *Store) HandleSubmitBadge(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	badge, _ := msg["badge"].(string)
	badgeSig, _ := msg["badge_sig"].(string)
	sigB64, _ := msg["signature"].(string)

	if badge == "" || badgeSig == "" {
		return nil, fmt.Errorf("submit_badge requires badge and badge_sig")
	}
	if err := st.verifyNodeSig(nodeID, "submit_badge:"+fmt.Sprint(nodeID)+":"+badge, sigB64); err != nil {
		return nil, err
	}

	b, err := st.verifyBadge(badge, badgeSig, nodeID)
	if err != nil {
		return nil, fmt.Errorf("badge verification failed: %w", err)
	}

	if ok := st.nodes.SubmitBadge(nodeID, badge, badgeSig, b.Provider, st.nodes.Now()); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	if st.cb.Save != nil {
		st.cb.Save()
	}
	if st.cb.Audit != nil {
		st.cb.Audit("identity.badge_submitted", "node_id", nodeID, "provider", b.Provider)
	}
	return map[string]interface{}{
		"type":     "submit_badge_ok",
		"node_id":  nodeID,
		"provider": b.Provider,
	}, nil
}

// HandleEnrollRecovery implements "enroll_recovery". The node proves
// current-key ownership; the enrollment statement (signed by the online
// badge key) carries the opaque identity commitment a future recovery must
// match. Only the commitment is stored — never the raw identity.
func (st *Store) HandleEnrollRecovery(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	enrollment, _ := msg["enrollment"].(string)
	enrollSig, _ := msg["enrollment_sig"].(string)
	sigB64, _ := msg["signature"].(string)

	if enrollment == "" || enrollSig == "" {
		return nil, fmt.Errorf("enroll_recovery requires enrollment and enrollment_sig")
	}

	e, err := st.verifyEnrollment(enrollment, enrollSig)
	if err != nil {
		return nil, fmt.Errorf("enrollment verification failed: %w", err)
	}
	if e.NodeID != nodeID {
		return nil, fmt.Errorf("enrollment node_id mismatch: statement=%d request=%d", e.NodeID, nodeID)
	}
	// Bind enrollment to the commitment value, so a stolen enrollment can't
	// be swapped for a different commitment.
	if err := st.verifyNodeSig(nodeID, "enroll_recovery:"+fmt.Sprint(nodeID)+":"+e.Commitment, sigB64); err != nil {
		return nil, err
	}

	if ok := st.nodes.SetRecoveryEnrollment(nodeID, e.Commitment, e.Provider); !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	if st.cb.Save != nil {
		st.cb.Save()
	}
	if st.cb.Audit != nil {
		st.cb.Audit("identity.recovery_enrolled", "node_id", nodeID, "provider", e.Provider)
	}
	return map[string]interface{}{
		"type":    "enroll_recovery_ok",
		"node_id": nodeID,
	}, nil
}

// HandleRecoverIdentity implements "recover_identity". This is the ONLY
// path that rotates a key without the old key. Authorization is a
// cold-key-signed recovery statement whose commitment must match the
// node's enrollment, whose nonce must be unused, and which must not have
// expired. On success the address is force-rotated to the new key and a
// notification is emitted (the owner can detect the recovery).
func (st *Store) HandleRecoverIdentity(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	statement, _ := msg["recovery"].(string)
	recSig, _ := msg["recovery_sig"].(string)
	newPubKeyB64, _ := msg["new_public_key"].(string)

	if statement == "" || recSig == "" || newPubKeyB64 == "" {
		return nil, fmt.Errorf("recover_identity requires recovery, recovery_sig, new_public_key")
	}
	newPubKey, err := pilotcrypto.DecodePublicKey(newPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid new_public_key: %w", err)
	}

	// Verify the recovery statement against the COLD recovery keyring
	// (checks signature + expiry). A compromised online badge key cannot
	// produce one.
	r, err := st.verifyRecovery(statement, recSig)
	if err != nil {
		return nil, fmt.Errorf("recovery verification failed: %w", err)
	}
	if r.NodeID != nodeID {
		return nil, fmt.Errorf("recovery node_id mismatch")
	}
	if r.NewPubKey != newPubKeyB64 {
		return nil, fmt.Errorf("recovery is not bound to this new key")
	}

	// The re-proven identity's commitment must match what was enrolled.
	storedCommitment, provider, ok := st.nodes.GetRecoveryEnrollment(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d is not enrolled for recovery", nodeID)
	}
	if r.Commitment != storedCommitment {
		return nil, fmt.Errorf("recovery identity does not match the enrolled identity")
	}

	// Single-use nonce: reject replays.
	if !st.consumeNonce(r.Nonce, time.Unix(r.Exp, 0)) {
		return nil, fmt.Errorf("recovery authorization already used")
	}

	oldPubKeyB64, err := st.nodes.ForceRotateKey(nodeID, newPubKey, st.nodes.Now())
	if err != nil {
		return nil, err
	}
	if st.cb.OnKeyRotated != nil {
		st.cb.OnKeyRotated(nodeID, oldPubKeyB64, newPubKeyB64)
	}
	if st.cb.RecordWAL != nil {
		st.cb.RecordWAL(nodeID, newPubKeyB64, st.nodes.Now().UTC().Format(time.RFC3339))
	}
	if st.cb.Save != nil {
		st.cb.Save()
	}
	// Notification: instant recovery has no veto, but the owner must be able
	// to DETECT it. Emit a distinct, audited event.
	if st.cb.Audit != nil {
		st.cb.Audit("node.recovered", "node_id", nodeID, "provider", provider)
	}
	if st.cb.Bus != nil {
		st.cb.Bus.Publish(events.Event{
			Source:  "identity",
			Type:    "node.recovered",
			Payload: map[string]any{"node_id": nodeID, "provider": provider},
		})
	}

	addr := protocol.Addr{Network: 0, Node: nodeID}
	return map[string]interface{}{
		"type":       "recover_identity_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"public_key": newPubKeyB64,
	}, nil
}

// consumeNonce records a recovery nonce as used (returns true) or reports
// it already used (false). Expired entries are pruned opportunistically.
func (st *Store) consumeNonce(nonce string, exp time.Time) bool {
	st.nonceMu.Lock()
	defer st.nonceMu.Unlock()
	now := st.nodes.Now()
	for n, e := range st.consumedNonces {
		if now.After(e) {
			delete(st.consumedNonces, n)
		}
	}
	if _, used := st.consumedNonces[nonce]; used {
		return false
	}
	st.consumedNonces[nonce] = exp
	return true
}
