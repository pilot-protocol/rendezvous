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

func TestHandleRegisterEndpointRatchet(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub := crypto.EncodePublicKey(id.PublicKey)
	sign := func(addr string) string {
		return base64.StdEncoding.EncodeToString(id.Sign([]byte("register:" + addr + ":" + pub)))
	}
	st := ppa003Store(t, false)
	reg := func(pk, addr, remote, sig string) error {
		m := map[string]interface{}{"public_key": pk, "listen_addr": addr}
		if sig != "" {
			m["signature"] = sig
		}
		_, e := st.HandleRegister(m, remote, nil, nil)
		return e
	}

	// 1. signed registration latches SigVerified
	if e := reg(pub, "10.0.0.1:5000", "10.0.0.1:5000", sign("10.0.0.1:5000")); e != nil {
		t.Fatalf("signed register: %v", e)
	}
	// 2. ATTACK: unsigned re-register of that key from a different endpoint — REJECTED
	if e := reg(pub, "10.9.9.9:5000", "10.9.9.9:5000", ""); e == nil {
		t.Fatal("unsigned endpoint relocation of a signature-verified key was ALLOWED (ratchet failed)")
	}
	// 3. legit signed move — allowed
	if e := reg(pub, "10.0.0.2:6000", "10.0.0.2:6000", sign("10.0.0.2:6000")); e != nil {
		t.Fatalf("signed endpoint move rejected: %v", e)
	}
	// 4. unsigned same-endpoint refresh — allowed (harmless)
	if e := reg(pub, "10.0.0.2:6000", "10.0.0.2:6000", ""); e != nil {
		t.Fatalf("unsigned same-endpoint refresh rejected: %v", e)
	}

	// 5. COMPAT: a key that never signed can still relocate unsigned (old agent)
	id2, _ := crypto.GenerateIdentity()
	pub2 := crypto.EncodePublicKey(id2.PublicKey)
	if e := reg(pub2, "10.1.1.1:5000", "10.1.1.1:5000", ""); e != nil {
		t.Fatalf("unsigned new node: %v", e)
	}
	if e := reg(pub2, "10.2.2.2:5000", "10.2.2.2:5000", ""); e != nil {
		t.Fatalf("unsigned old-agent endpoint change BLOCKED (compat break): %v", e)
	}
}
