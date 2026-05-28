// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	pilotcrypto "github.com/pilot-protocol/common/crypto"
)

// rotateOKView lets UpdateNodeKey succeed and tracks the new key.
type rotateOKView struct {
	*adminCheckingView
	storedPubKey []byte
}

func (v *rotateOKView) LookupNodeKey(uint32) ([]byte, bool) {
	return v.storedPubKey, v.storedPubKey != nil
}
func (v *rotateOKView) UpdateNodeKey(_ uint32, _, newPK []byte, _ time.Time) (string, error) {
	old := v.storedPubKey
	v.storedPubKey = newPK
	return base64.StdEncoding.EncodeToString(old), nil
}

func TestHandleRotateKey_HappyPath(t *testing.T) {
	t.Parallel()
	// Build an initial keypair.
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPubB64 := pilotcrypto.EncodePublicKey(newPub)

	view := &rotateOKView{
		adminCheckingView: &adminCheckingView{
			fakeNodeView: &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}},
			adminOK:      true,
		},
		storedPubKey: oldPub,
	}
	st := NewStore(view, Callbacks{
		Save:            func() {},
		Audit:           func(string, ...any) {},
		IncKeyRotations: func() {},
		RecordWAL:       func(uint32, string, string) {},
		OnKeyRotated:    func(uint32, string, string) {},
	})

	// Sign the rotate challenge with the OLD key.
	challenge := fmt.Sprintf("rotate:%d:%s", 1, newPubB64)
	sig := ed25519.Sign(oldPriv, []byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	resp, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(1),
		"signature":      sigB64,
		"new_public_key": newPubB64,
	})
	if err != nil {
		t.Fatalf("HandleRotateKey: %v", err)
	}
	if resp["public_key"] != newPubB64 {
		t.Errorf("public_key = %v, want %s", resp["public_key"], newPubB64)
	}
}

func TestHandleRotateKey_BadSignatureFails(t *testing.T) {
	t.Parallel()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPubB64 := pilotcrypto.EncodePublicKey(newPub)

	view := &rotateOKView{
		adminCheckingView: &adminCheckingView{
			fakeNodeView: &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}},
			adminOK:      true,
		},
		storedPubKey: oldPub,
	}
	st := NewStore(view, Callbacks{Save: func() {}})

	// Use a random/wrong signature.
	bogus := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	_, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(1),
		"signature":      bogus,
		"new_public_key": newPubB64,
	})
	if err == nil {
		t.Error("expected signature-verification error")
	}
}

func TestHandleRotateKey_BadSignatureBase64(t *testing.T) {
	t.Parallel()
	oldPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	view := &rotateOKView{
		adminCheckingView: &adminCheckingView{
			fakeNodeView: &fakeNodeView{nodes: map[uint32]fakeNode{1: {}}},
			adminOK:      true,
		},
		storedPubKey: oldPub,
	}
	st := NewStore(view, Callbacks{})
	_, err := st.HandleRotateKey(map[string]interface{}{
		"node_id":        float64(1),
		"signature":      "!!!",
		"new_public_key": pilotcrypto.EncodePublicKey(newPub),
	})
	if err == nil {
		t.Error("expected b64 decode error")
	}
}
