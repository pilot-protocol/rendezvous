// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

func TestHandleRegisterSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := crypto.EncodePublicKey(pub)
	const listenAddr = "10.0.0.1:4000"

	sign := func(p ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(
			ed25519.Sign(p, []byte(fmt.Sprintf("register:%s:%s", listenAddr, pubB64))))
	}
	goodSig := sign(priv)

	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeySig := sign(otherPriv)

	regMsg := func(sig string) map[string]interface{} {
		m := map[string]interface{}{
			"public_key":  pubB64,
			"listen_addr": listenAddr,
			"owner":       "alice",
		}
		if sig != "" {
			m["signature"] = sig
		}
		return m
	}

	cases := []struct {
		name    string
		strict  bool
		sig     string
		wantErr bool
	}{
		{"unsigned accepted by default (backward compatible)", false, "", false},
		{"unsigned rejected when strict", true, "", true},
		{"valid signature accepted (lenient)", false, goodSig, false},
		{"valid signature accepted (strict)", true, goodSig, false},
		{"wrong-key signature rejected (lenient verify-if-present)", false, wrongKeySig, true},
		{"wrong-key signature rejected (strict)", true, wrongKeySig, true},
		{"malformed signature rejected", false, "not-base64!!", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			st.cb.StrictRegistrationAuth = func() bool { return tc.strict }
			resp, err := st.HandleRegister(regMsg(tc.sig), listenAddr, nil, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got resp=%v", resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp["type"] != "register_ok" {
				t.Fatalf("expected register_ok, got %v", resp)
			}
		})
	}
}
