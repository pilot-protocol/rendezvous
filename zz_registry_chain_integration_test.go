// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
	pilotcrypto "github.com/pilot-protocol/common/crypto"
)

// Fixed test keys. To exercise the REAL badgeverify path (no stubs), run:
//
//	GOWORK=off go test ./ -run TestRegistryChainRealVerification \
//	  -ldflags "-X 'github.com/pilot-protocol/common/badgeverify.keyringB64=bdg-v1=kIyseGuqMq6Y/mpk3Z8KD21JpSykJCyXQSWw05OJKb8=' \
//	            -X 'github.com/pilot-protocol/common/badgeverify.recoveryKeyringB64=rec-v1=kkNP/GeIoyULdJVjfFH2Yqmgg/QgcppCkjzHYiMPUXs='"
//
// Without those ldflags the keyring holds all-zero placeholders and the
// test skips (verification correctly fails closed).
const (
	itIssuerPrivB64 = "7zyivJ460ALCc9W29LDCgGdDUZ9T3fWTKOF3HyPfOkiQjKx4a6oyrpj+amTdnwoPbUmlLKQkLJdBJbDTk4kpvw=="
	itColdPrivB64   = "MINhBLxWw93Ga2a3pund99bu3Cj3VqXaQu8awgRLXhiSQ0/8Z4ijJQt0lWN8UfZiqaCD9CBymkKSPMdiIw9Rew=="
	itIssuerKid     = "bdg-v1"
	itColdKid       = "rec-v1"
)

func mustPriv(t *testing.T, b64 string) ed25519.PrivateKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return ed25519.PrivateKey(raw)
}

func b64sign(priv ed25519.PrivateKey, s string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(s)))
}

// TestRegistryChainRealVerification drives the full registry-bound chain —
// submit_badge → lookup → enroll_recovery → recover_identity — through the
// REAL Server handlers and REAL badgeverify verification (keys pinned via
// -ldflags, exactly like production). No stubbed verifiers.
func TestRegistryChainRealVerification(t *testing.T) {
	issuerPriv := mustPriv(t, itIssuerPrivB64)
	coldPriv := mustPriv(t, itColdPrivB64)

	const nodeID = uint32(0x1ABCD)

	// Mint a probe badge; if the keyring isn't pinned, verification fails
	// closed and we skip with instructions.
	mintBadge := func() (string, string) {
		b := badgeverify.Badge{NodeID: nodeID, Provider: "github", VerifiedAt: time.Now().Unix(), Kid: itIssuerKid}
		s, _ := badgeverify.Canonical(b)
		return s, b64sign(issuerPriv, s)
	}
	badge, badgeSig := mintBadge()
	if _, err := badgeverify.VerifyForNode(badge, badgeSig, nodeID); errors.Is(err, badgeverify.ErrNoKey) {
		t.Skip("keyring not pinned; re-run with -ldflags pinning the test keys (see file header)")
	}

	s := newTestServer(t, "admin")

	// A registered node whose CURRENT key we control (for the node-signed
	// submit_badge / enroll_recovery steps).
	nodeIdent, err := pilotcrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("node keygen: %v", err)
	}
	s.mu.Lock()
	s.nodes[nodeID] = &NodeInfo{ID: nodeID, PublicKey: nodeIdent.PublicKey, Networks: []uint16{0}}
	s.pubKeyIdx[pilotcrypto.EncodePublicKey(nodeIdent.PublicKey)] = nodeID
	s.mu.Unlock()

	// 1. submit_badge — real badge, real verification, node-signed.
	nodeSig := b64sign(ed25519.PrivateKey(nodeIdent.PrivateKey), "submit_badge:"+fmt.Sprint(nodeID)+":"+badge)
	if _, err := s.identity.HandleSubmitBadge(map[string]interface{}{
		"node_id": float64(nodeID), "badge": badge, "badge_sig": badgeSig, "signature": nodeSig,
	}); err != nil {
		t.Fatalf("submit_badge: %v", err)
	}

	// 2. lookup — surfaces verified + badge, never the raw identity.
	lr, err := s.directory.HandleLookup(map[string]interface{}{"node_id": float64(nodeID)})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if lr["verified"] != true || lr["badge"] != badge {
		t.Fatalf("lookup did not surface verified badge: %+v", lr)
	}
	if _, leaked := lr["external_id"]; leaked {
		t.Fatal("lookup leaked external_id")
	}

	// 3. enroll_recovery — real enrollment (online key), node-signed.
	const commitment = "COMMIT-OPAQUE=="
	enr := badgeverify.Enrollment{NodeID: nodeID, Provider: "github", Commitment: commitment, IssuedAt: time.Now().Unix(), Kid: itIssuerKid}
	enrStr, _ := badgeverify.CanonicalEnrollment(enr)
	enrSig := b64sign(issuerPriv, enrStr)
	nodeSig2 := b64sign(ed25519.PrivateKey(nodeIdent.PrivateKey), "enroll_recovery:"+fmt.Sprint(nodeID)+":"+commitment)
	if _, err := s.identity.HandleEnrollRecovery(map[string]interface{}{
		"node_id": float64(nodeID), "enrollment": enrStr, "enrollment_sig": enrSig, "signature": nodeSig2,
	}); err != nil {
		t.Fatalf("enroll_recovery: %v", err)
	}

	// 4. recover_identity — cold-key authorization, NO old node key. Force-
	// rotates the address to a brand-new key.
	newIdent, _ := pilotcrypto.GenerateIdentity()
	newPubB64 := pilotcrypto.EncodePublicKey(newIdent.PublicKey)
	rec := badgeverify.Recovery{
		NodeID: nodeID, NewPubKey: newPubB64, Commitment: commitment,
		Exp: time.Now().Add(5 * time.Minute).Unix(), Nonce: "nonce-int-1", Kid: itColdKid,
	}
	recStr, _ := badgeverify.CanonicalRecovery(rec)
	recSig := b64sign(coldPriv, recStr)
	if _, err := s.identity.HandleRecoverIdentity(map[string]interface{}{
		"node_id": float64(nodeID), "recovery": recStr, "recovery_sig": recSig, "new_public_key": newPubB64,
	}); err != nil {
		t.Fatalf("recover_identity: %v", err)
	}

	// The address was force-rotated to the new key — recovery worked without
	// the old key.
	s.mu.RLock()
	gotKey := pilotcrypto.EncodePublicKey(s.nodes[nodeID].PublicKey)
	s.mu.RUnlock()
	if gotKey != newPubB64 {
		t.Fatalf("recovery did not rotate the address key: got %s want %s", gotKey, newPubB64)
	}
}

// TestForceRotateKeyClearsBadge pins that a recovery (force-rotate) does NOT
// let the new key holder inherit the prior owner's verification badge — the
// badge may attest a different external identity than the recoverer.
func TestForceRotateKeyClearsBadge(t *testing.T) {
	s := newTestServer(t, "admin")
	const nodeID = uint32(0x2BADC0DE)
	id, err := pilotcrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s.mu.Lock()
	s.nodes[nodeID] = &NodeInfo{
		ID: nodeID, PublicKey: id.PublicKey,
		Badge: "pilotbadge:v1:1:github:1:0:bdg-v1:", BadgeSig: "sig",
		VerificationProvider: "github", VerifiedAt: time.Now(),
	}
	s.mu.Unlock()

	newID, err := pilotcrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("new keygen: %v", err)
	}
	if _, err := s.ForceRotateKey(nodeID, newID.PublicKey, time.Now()); err != nil {
		t.Fatalf("ForceRotateKey: %v", err)
	}

	s.mu.RLock()
	n := s.nodes[nodeID]
	s.mu.RUnlock()
	if n.Badge != "" || n.BadgeSig != "" || n.VerificationProvider != "" || !n.VerifiedAt.IsZero() {
		t.Fatalf("verification badge not cleared after recovery: badge=%q provider=%q verified_at=%v",
			n.Badge, n.VerificationProvider, n.VerifiedAt)
	}
}
