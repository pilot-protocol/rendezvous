// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
)

func TestNewStore_DefaultVerifyFuncsAreSet(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	if st.verifyBadge == nil {
		t.Fatal("verifyBadge default should be set")
	}
	if st.verifyEnrollment == nil {
		t.Fatal("verifyEnrollment default should be set")
	}
	if st.verifyRecovery == nil {
		t.Fatal("verifyRecovery default should be set")
	}
	if st.consumedNonces == nil {
		t.Fatal("consumedNonces map should be initialized")
	}
}

func TestDefaultVerifyBadge_RejectsMalformedInput(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	_, err := st.verifyBadge("not-a-badge", "sig", 1)
	if err == nil || !errors.Is(err, badgeverify.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}

func TestDefaultVerifyBadge_RejectsUnknownKid(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	b := badgeverify.Badge{NodeID: 1, Provider: "github", Kid: "no-such-kid"}
	s, err := badgeverify.Canonical(b)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(s)))
	_, err = st.verifyBadge(s, sig, 1)
	if err == nil || !errors.Is(err, badgeverify.ErrNoKey) {
		t.Fatalf("expected ErrNoKey (proves the default wraps the real badgeverify keyring), got %v", err)
	}
}

func TestDefaultVerifyBadge_RejectsWrongSignerForPinnedKid(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	b := badgeverify.Badge{NodeID: 1, Provider: "github", Kid: "bdg-v1"}
	s, err := badgeverify.Canonical(b)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(s)))
	_, err = st.verifyBadge(s, sig, 1)
	if err == nil || errors.Is(err, badgeverify.ErrMalformed) || errors.Is(err, badgeverify.ErrNoKey) {
		t.Fatalf("expected a signature-verification failure, got %v", err)
	}
}

func TestDefaultVerifyEnrollment_RejectsMalformedInput(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	_, err := st.verifyEnrollment("not-an-enrollment", "sig")
	if err == nil || !errors.Is(err, badgeverify.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}

func TestDefaultVerifyEnrollment_RejectsUnknownKid(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	e := badgeverify.Enrollment{NodeID: 1, Provider: "github", Commitment: "C", Kid: "no-such-kid"}
	s, err := badgeverify.CanonicalEnrollment(e)
	if err != nil {
		t.Fatalf("CanonicalEnrollment: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(s)))
	_, err = st.verifyEnrollment(s, sig)
	if err == nil || !errors.Is(err, badgeverify.ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

func TestDefaultVerifyRecovery_RejectsMalformedInput(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	_, err := st.verifyRecovery("not-a-recovery", "sig")
	if err == nil || !errors.Is(err, badgeverify.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}

func TestDefaultVerifyRecovery_RejectsUnknownKid(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	r := badgeverify.Recovery{
		NodeID: 1, NewPubKey: "pk", Commitment: "C",
		Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n", Kid: "no-such-kid",
	}
	s, err := badgeverify.CanonicalRecovery(r)
	if err != nil {
		t.Fatalf("CanonicalRecovery: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(s)))
	_, err = st.verifyRecovery(s, sig)
	if err == nil || !errors.Is(err, badgeverify.ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

func TestFakeNodeView_SubmitBadgeRoundtrip(t *testing.T) {
	t.Parallel()
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}}
	now := time.Now()
	if ok := fv.SubmitBadge(1, "badge-str", "badge-sig", "github", now); !ok {
		t.Fatal("SubmitBadge should succeed for existing node")
	}
	n := fv.nodes[1]
	if n.badge != "badge-str" || n.badgeSig != "badge-sig" || n.provider != "github" {
		t.Fatalf("badge fields not stored: %+v", n)
	}
}

func TestFakeNodeView_SubmitBadgeMissingNode(t *testing.T) {
	t.Parallel()
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{}}
	if ok := fv.SubmitBadge(99, "b", "s", "github", time.Now()); ok {
		t.Fatal("SubmitBadge should fail for a missing node")
	}
}

func TestFakeNodeView_SetGetRecoveryEnrollmentRoundtrip(t *testing.T) {
	t.Parallel()
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}}
	if ok := fv.SetRecoveryEnrollment(1, "COMMIT==", "github"); !ok {
		t.Fatal("SetRecoveryEnrollment should succeed for existing node")
	}
	commitment, provider, ok := fv.GetRecoveryEnrollment(1)
	if !ok || commitment != "COMMIT==" || provider != "github" {
		t.Fatalf("got (%q, %q, %v)", commitment, provider, ok)
	}
}

func TestFakeNodeView_GetRecoveryEnrollmentNotEnrolled(t *testing.T) {
	t.Parallel()
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}}
	if _, _, ok := fv.GetRecoveryEnrollment(1); ok {
		t.Fatal("expected ok=false for a node with no recovery enrollment")
	}
	if _, _, ok := fv.GetRecoveryEnrollment(99); ok {
		t.Fatal("expected ok=false for a missing node")
	}
}

func TestFakeNodeView_ForceRotateKeySwapsAndReturnsOld(t *testing.T) {
	t.Parallel()
	oldKey := []byte("old-key-32-bytes-of-filler-data")
	newKey := []byte("new-key-32-bytes-of-filler-data")
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{1: {pubKey: oldKey}}}

	oldB64, err := fv.ForceRotateKey(1, newKey, time.Now())
	if err != nil {
		t.Fatalf("ForceRotateKey: %v", err)
	}
	if oldB64 != base64.StdEncoding.EncodeToString(oldKey) {
		t.Fatalf("old key mismatch: got %q", oldB64)
	}
	got, _ := fv.LookupNodeKey(1)
	if string(got) != string(newKey) {
		t.Fatalf("key was not swapped: got %q", got)
	}
}

func TestFakeNodeView_ForceRotateKeyMissingNode(t *testing.T) {
	t.Parallel()
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{}}
	if _, err := fv.ForceRotateKey(99, []byte("k"), time.Now()); err == nil {
		t.Fatal("expected an error for a missing node")
	}
}
