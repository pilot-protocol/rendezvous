// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/reqsig"
)

// seedVerifyNode registers a node with a real keypair plus the network
// memberships the verification tests exercise.
func seedVerifyNode(t *testing.T, s *Server, nodeID uint32, owner string, networks []uint16) *crypto.Identity {
	t.Helper()
	id, _ := seedNodeWithIdentity(t, s, nodeID, owner)
	s.mu.Lock()
	s.nodes[nodeID].Networks = append([]uint16(nil), networks...)
	s.mu.Unlock()
	return id
}

// signedEnvelope builds a canonical envelope for (network, node) at ts and
// signs it with id.
func signedEnvelope(t *testing.T, id *crypto.Identity, network uint16, node uint32, ts int64) (canonical, sigB64 string) {
	t.Helper()
	nonce, err := reqsig.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	e := reqsig.Envelope{
		Network:   network,
		Node:      node,
		Timestamp: ts,
		Nonce:     nonce,
		BodyHash:  reqsig.HashBody([]byte("test-body")),
		Audience:  "test.consumer",
	}
	canonical, sigB64, err = reqsig.Sign(id.PrivateKey, e)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	return canonical, sigB64
}

// assertUniformFailure checks the no-existence-oracle contract: valid:false
// with every non-verdict field zeroed, plus a signed NEGATIVE verdict that
// verifies against the server's verdict key.
func assertUniformFailure(t *testing.T, s *Server, resp VerifyResponse, label string) {
	t.Helper()
	if resp.Valid || resp.Online || resp.NetworkMember {
		t.Fatalf("%s: flags not all false: %+v", label, resp)
	}
	if resp.Address != "" || resp.LastSeen != "" || resp.Nonce != "" {
		t.Fatalf("%s: string fields not zeroed: %+v", label, resp)
	}
	if resp.LastSeenUnix != 0 || resp.KeyGeneration != 0 || resp.StaleThresholdSecs != 0 {
		t.Fatalf("%s: numeric fields not zeroed: %+v", label, resp)
	}
	if resp.Verdict == "" || resp.VerdictSig == "" || resp.VerdictKid == "" {
		t.Fatalf("%s: failure must still carry a signed negative verdict: %+v", label, resp)
	}
	v, err := reqsig.VerifyVerdictWithKey(s.VerdictPublicKey(), resp.Verdict, resp.VerdictSig)
	if err != nil {
		t.Fatalf("%s: negative verdict does not verify: %v", label, err)
	}
	if v.Valid || v.Online || v.NetworkMember {
		t.Fatalf("%s: negative verdict flags not all false: %+v", label, v)
	}
	if v.LastSeenUnix != 0 || v.KeyGeneration != 0 {
		t.Fatalf("%s: negative verdict leaks node state: %+v", label, v)
	}
}

// TestVerifyRequestValid locks down the happy path: correct signature from a
// registered, recently-seen node that is a member of the envelope's network.
func TestVerifyRequestValid(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	id := seedVerifyNode(t, s, 100, "alice", []uint16{0, 7})

	s.mu.Lock()
	s.nodes[100].KeyMeta.RotateCount = 3
	s.mu.Unlock()

	canonical, sigB64 := signedEnvelope(t, id, 7, 100, time.Now().Unix())
	resp := s.VerifyRequest(canonical, sigB64)

	if !resp.Valid {
		t.Fatalf("valid = false, want true: %+v", resp)
	}
	if !resp.Online {
		t.Fatalf("online = false for a just-seeded node: %+v", resp)
	}
	if !resp.NetworkMember {
		t.Fatalf("network_member = false, node is in network 7: %+v", resp)
	}
	if resp.Address == "" {
		t.Fatalf("address missing on valid response")
	}
	if resp.Nonce == "" {
		t.Fatalf("nonce not echoed on valid response")
	}
	if resp.KeyGeneration != 3 {
		t.Fatalf("key_generation = %d, want 3", resp.KeyGeneration)
	}
	if resp.LastSeenUnix == 0 || resp.LastSeen == "" {
		t.Fatalf("last_seen fields missing: %+v", resp)
	}
	if want := int64(s.StaleNodeThreshold() / time.Second); resp.StaleThresholdSecs != want {
		t.Fatalf("stale_threshold_secs = %d, want %d", resp.StaleThresholdSecs, want)
	}
	if resp.VerdictKid != s.VerdictKid() {
		t.Fatalf("verdict_kid = %q, want %q", resp.VerdictKid, s.VerdictKid())
	}

	// The verdict must verify offline against the published key and bind
	// the exact envelope by hash.
	v, err := reqsig.VerifyVerdictWithKey(s.VerdictPublicKey(), resp.Verdict, resp.VerdictSig)
	if err != nil {
		t.Fatalf("verdict verify: %v", err)
	}
	if v.EnvHash != reqsig.HashEnvelope(canonical) {
		t.Fatalf("verdict env hash mismatch")
	}
	if !v.Valid || !v.Online || !v.NetworkMember {
		t.Fatalf("verdict flags = %+v, want all true", v)
	}
	if v.Network != 7 || v.Node != 100 {
		t.Fatalf("verdict address = %d/%d, want 7/100", v.Network, v.Node)
	}
	if v.KeyGeneration != 3 {
		t.Fatalf("verdict key generation = %d, want 3", v.KeyGeneration)
	}
	if v.LastSeenUnix != resp.LastSeenUnix {
		t.Fatalf("verdict last_seen %d != response %d", v.LastSeenUnix, resp.LastSeenUnix)
	}
}

// TestVerifyRequestNonMember: a valid signature for a network the node does
// NOT belong to yields valid:true but network_member:false.
func TestVerifyRequestNonMember(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	id := seedVerifyNode(t, s, 110, "bob", []uint16{0, 7})

	canonical, sigB64 := signedEnvelope(t, id, 9, 110, time.Now().Unix())
	resp := s.VerifyRequest(canonical, sigB64)
	if !resp.Valid {
		t.Fatalf("valid = false: %+v", resp)
	}
	if resp.NetworkMember {
		t.Fatalf("network_member = true for non-member network 9")
	}
}

// TestVerifyRequestUniformFailures: wrong-key signature, unknown node, stale
// timestamp, expired key, and unparseable envelope must all produce the SAME
// uniform valid:false shape — no existence oracle.
func TestVerifyRequestUniformFailures(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	id := seedVerifyNode(t, s, 120, "carol", []uint16{0})
	now := time.Now().Unix()

	// Expired-key node.
	idExpired := seedVerifyNode(t, s, 121, "dave", []uint16{0})
	s.mu.Lock()
	s.nodes[121].KeyMeta.ExpiresAt = time.Now().Add(-time.Hour)
	s.mu.Unlock()

	attacker, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen attacker: %v", err)
	}

	wrongSigCanon, wrongSig := signedEnvelope(t, attacker, 0, 120, now)
	unknownCanon, unknownSig := signedEnvelope(t, id, 0, 9999, now)
	staleCanon, staleSig := signedEnvelope(t, id, 0, 120, now-400)
	expiredCanon, expiredSig := signedEnvelope(t, idExpired, 0, 121, now)

	cases := []struct {
		label     string
		canonical string
		sig       string
	}{
		{"wrong_key_signature", wrongSigCanon, wrongSig},
		{"unknown_node", unknownCanon, unknownSig},
		{"stale_timestamp", staleCanon, staleSig},
		{"expired_key", expiredCanon, expiredSig},
		{"garbage_envelope", "not-an-envelope", "bm90LWEtc2ln"},
	}
	for _, tc := range cases {
		resp := s.VerifyRequest(tc.canonical, tc.sig)
		assertUniformFailure(t, s, resp, tc.label)
	}
}

// TestVerifyRequestOnlineWindow: online must flip to false once LastSeen is
// older than the 180s verifyOnlineWindow, while validity is unaffected —
// and it must NOT use the 30-minute StaleNodeThreshold.
func TestVerifyRequestOnlineWindow(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	id := seedVerifyNode(t, s, 130, "erin", []uint16{0})

	s.mu.Lock()
	s.nodes[130].SetLastSeen(time.Now().Add(-verifyOnlineWindow - time.Second))
	s.mu.Unlock()

	canonical, sigB64 := signedEnvelope(t, id, 0, 130, time.Now().Unix())
	resp := s.VerifyRequest(canonical, sigB64)
	if !resp.Valid {
		t.Fatalf("valid = false: %+v", resp)
	}
	if resp.Online {
		t.Fatalf("online = true for node last seen %s ago", verifyOnlineWindow+time.Second)
	}
	if resp.LastSeenUnix == 0 {
		t.Fatalf("last_seen_unix should still be reported for a valid node")
	}

	v, err := reqsig.VerifyVerdictWithKey(s.VerdictPublicKey(), resp.Verdict, resp.VerdictSig)
	if err != nil {
		t.Fatalf("verdict verify: %v", err)
	}
	if v.Online {
		t.Fatalf("verdict online = true, want false")
	}
}
