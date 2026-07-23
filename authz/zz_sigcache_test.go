// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync/atomic"
	"testing"

	"github.com/pilot-protocol/rendezvous/authz"
)

func TestSigCache_SecondIdenticalVerifySkipsCryptoVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	challenge := "sigcache:hit:1"
	sig := ed25519.Sign(priv, []byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	msg := map[string]interface{}{"signature": sigB64}

	var verifyCalls atomic.Int32
	authz.SetOnSignatureVerify(func(bool) { verifyCalls.Add(1) })
	defer authz.SetOnSignatureVerify(nil)

	if err := authz.VerifyNodeSignature(pub, "", msg, challenge); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("verifyCalls after first call = %d, want 1", got)
	}

	if err := authz.VerifyNodeSignature(pub, "", msg, challenge); err != nil {
		t.Fatalf("second (cached) verify: %v", err)
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("verifyCalls after second call = %d, want 1 (cache hit must not exercise crypto.Verify)", got)
	}
}

func TestSigCache_TamperedSignatureNeverCached(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	challenge := "sigcache:tamper:1"
	sig := ed25519.Sign(priv, []byte(challenge))
	sig[0] ^= 0xFF // tamper with the signature bytes
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	msg := map[string]interface{}{"signature": sigB64}

	var verifyCalls atomic.Int32
	authz.SetOnSignatureVerify(func(bool) { verifyCalls.Add(1) })
	defer authz.SetOnSignatureVerify(nil)

	if err := authz.VerifyNodeSignature(pub, "", msg, challenge); err == nil {
		t.Fatal("tampered signature: expected error, got nil")
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("verifyCalls after first (failing) call = %d, want 1", got)
	}

	if err := authz.VerifyNodeSignature(pub, "", msg, challenge); err == nil {
		t.Fatal("tampered signature (retry): expected error, got nil")
	}
	if got := verifyCalls.Load(); got != 2 {
		t.Fatalf("verifyCalls after second (failing) call = %d, want 2 (negative results must never be cached)", got)
	}
}

func TestSigCache_NilPubKeyAdminTokenPathUnchanged(t *testing.T) {
	var verifyCalls atomic.Int32
	authz.SetOnSignatureVerify(func(bool) { verifyCalls.Add(1) })
	defer authz.SetOnSignatureVerify(nil)

	msg := map[string]interface{}{"admin_token": "ADM"}
	if err := authz.VerifyNodeSignature(nil, "ADM", msg, "challenge"); err != nil {
		t.Fatalf("nil pubkey + valid admin token: %v", err)
	}
	badMsg := map[string]interface{}{"admin_token": "wrong"}
	if err := authz.VerifyNodeSignature(nil, "ADM", badMsg, "challenge"); err == nil {
		t.Fatal("nil pubkey + invalid admin token: expected error")
	}
	if got := verifyCalls.Load(); got != 0 {
		t.Fatalf("verifyCalls = %d, want 0 (admin-token fallback must never touch the sig-verify hook/cache)", got)
	}
}
