// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"encoding/base64"
	"testing"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/rendezvous/authz"
)

func ppa003Store(t *testing.T, require bool) *Store {
	t.Helper()
	st := newTestStore(t)
	st.cb.VerifyNodeSignature = authz.VerifyNodeSignature
	if require {
		st.cb.RequireRegisterSignature = func() bool { return true }
	}
	return st
}

func TestHandleRegisterSignatureVerifyIfPresent(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	pubB64 := crypto.EncodePublicKey(id.PublicKey)
	addr := "10.0.0.7:4000"
	sigB64 := base64.StdEncoding.EncodeToString(id.Sign([]byte("register:" + addr + ":" + pubB64)))

	t.Run("valid signature accepted", func(t *testing.T) {
		st := ppa003Store(t, false)
		resp, err := st.HandleRegister(map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": addr,
			"signature":   sigB64,
		}, addr, nil, nil)
		if err != nil {
			t.Fatalf("valid signed registration rejected: %v", err)
		}
		if resp["type"] != "register_ok" {
			t.Fatalf("expected register_ok, got %v", resp["type"])
		}
	})

	t.Run("invalid signature rejected", func(t *testing.T) {
		st := ppa003Store(t, false)
		bad := id.Sign([]byte("register:" + addr + ":" + pubB64))
		bad[0] ^= 0xFF
		_, err := st.HandleRegister(map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": addr,
			"signature":   base64.StdEncoding.EncodeToString(bad),
		}, addr, nil, nil)
		if err == nil {
			t.Fatal("registration with a forged signature was accepted")
		}
	})

	t.Run("wrong listen_addr rejected", func(t *testing.T) {
		st := ppa003Store(t, false)
		_, err := st.HandleRegister(map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": "10.0.0.9:4000",
			"signature":   sigB64,
		}, addr, nil, nil)
		if err == nil {
			t.Fatal("signature bound to a different listen_addr was accepted")
		}
	})

	t.Run("unsigned accepted for compat", func(t *testing.T) {
		st := ppa003Store(t, false)
		if _, err := st.HandleRegister(map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": addr,
		}, addr, nil, nil); err != nil {
			t.Fatalf("unsigned registration rejected (compat break): %v", err)
		}
	})

	t.Run("unsigned rejected when required", func(t *testing.T) {
		st := ppa003Store(t, true)
		if _, err := st.HandleRegister(map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": addr,
		}, addr, nil, nil); err == nil {
			t.Fatal("unsigned registration accepted despite RequireRegisterSignature")
		}
	})
}
