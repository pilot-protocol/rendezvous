// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"encoding/base64"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// The PPA-003 attack: an unauthenticated stranger re-registers a victim's
// public key pointing at an attacker-controlled address, so every peer that
// resolves the victim is sent to the attacker. Once the victim has registered
// with a valid signature, the ratchet must refuse that relocation — while
// leaving never-signed (old-agent) keys free to move.
func TestRegisterEndpointRatchet(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub := crypto.EncodePublicKey(id.PublicKey)
	sign := func(addr string) string {
		return base64.StdEncoding.EncodeToString(id.Sign([]byte("register:" + addr + ":" + pub)))
	}
	st := newTestStore(t)
	reg := func(pk, addr, sig string) error {
		m := map[string]interface{}{"public_key": pk, "listen_addr": addr}
		if sig != "" {
			m["signature"] = sig
		}
		_, e := st.HandleRegister(m, addr, nil, nil)
		return e
	}

	if e := reg(pub, "10.0.0.1:5000", sign("10.0.0.1:5000")); e != nil {
		t.Fatalf("signed register rejected: %v", e)
	}

	if e := reg(pub, "10.9.9.9:5000", ""); e == nil {
		t.Fatal("ATTACK SUCCEEDED: unsigned registration relocated a signature-verified key's endpoint")
	}

	st.mu.RLock()
	nodeID := st.pubKeyIdx[pub]
	addr := st.nodes[nodeID].RealAddr
	st.mu.RUnlock()
	if addr != "10.0.0.1:5000" {
		t.Fatalf("endpoint was mutated by the rejected attack: %q", addr)
	}

	if e := reg(pub, "10.0.0.2:6000", sign("10.0.0.2:6000")); e != nil {
		t.Fatalf("legitimate signed endpoint move rejected: %v", e)
	}
	// An unsigned registration for a signature-verified key is refused even at
	// the same endpoint — a signing daemon always signs, so this only ever
	// arrives from an attacker.
	if e := reg(pub, "10.0.0.2:6000", ""); e == nil {
		t.Fatal("unsigned re-register of a signature-verified key was accepted")
	}

	// Compat: a key that never signed must still be able to move (old agents).
	id2, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := crypto.EncodePublicKey(id2.PublicKey)
	if e := reg(pub2, "10.1.1.1:5000", ""); e != nil {
		t.Fatalf("unsigned new node rejected: %v", e)
	}
	if e := reg(pub2, "10.2.2.2:5000", ""); e != nil {
		t.Fatalf("COMPAT BREAK: unsigned old-agent endpoint change was blocked: %v", e)
	}
}
