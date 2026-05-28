// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/pilot-protocol/rendezvous/authz"
)

func TestChecker_AccessorsAndSetters(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("admin", "dash")
	if got := c.AdminToken(); got != "admin" {
		t.Errorf("AdminToken = %q", got)
	}
	if got := c.DashboardToken(); got != "dash" {
		t.Errorf("DashboardToken = %q", got)
	}
	c.SetAdminToken("new-admin")
	c.SetDashboardToken("new-dash")
	if c.AdminToken() != "new-admin" {
		t.Error("SetAdminToken did not apply")
	}
	if c.DashboardToken() != "new-dash" {
		t.Error("SetDashboardToken did not apply")
	}
}

func TestChecker_RequireAdminTokenWith(t *testing.T) {
	t.Parallel()
	c := authz.NewChecker("admin", "")
	// Valid pre-copied token.
	if err := c.RequireAdminTokenWith(map[string]interface{}{"admin_token": "admin"}, "admin"); err != nil {
		t.Errorf("valid: %v", err)
	}
	// Mismatch.
	if err := c.RequireAdminTokenWith(map[string]interface{}{"admin_token": "wrong"}, "admin"); err == nil {
		t.Error("mismatch: want error")
	}
	// Empty server-side token = disabled.
	if err := c.RequireAdminTokenWith(map[string]interface{}{"admin_token": "anything"}, ""); err == nil {
		t.Error("disabled: want error")
	}
}

func TestVerifyNodeSignature_NoPubKeyAdminTokenFallback(t *testing.T) {
	t.Parallel()
	// pubKey nil + valid admin_token → success.
	if err := authz.VerifyNodeSignature(nil, "ADM", map[string]interface{}{"admin_token": "ADM"}, "challenge"); err != nil {
		t.Errorf("no-pub + valid token: %v", err)
	}
	// pubKey nil + wrong token → error.
	if err := authz.VerifyNodeSignature(nil, "ADM", map[string]interface{}{"admin_token": "wrong"}, "x"); err == nil {
		t.Error("no-pub + wrong token: want error")
	}
}

func TestVerifyNodeSignature_HappyPath(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	challenge := "challenge:42"
	sig := ed25519.Sign(priv, []byte(challenge))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := authz.VerifyNodeSignature(pub, "", map[string]interface{}{"signature": sigB64}, challenge); err != nil {
		t.Errorf("happy: %v", err)
	}
}

func TestVerifyNodeSignature_MissingSignatureField(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := authz.VerifyNodeSignature(pub, "", map[string]interface{}{}, "x"); err == nil {
		t.Error("missing sig: want error")
	}
}

func TestVerifyNodeSignature_BadSignatureEncoding(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := authz.VerifyNodeSignature(pub, "", map[string]interface{}{"signature": "!!!"}, "x"); err == nil {
		t.Error("bad b64: want error")
	}
}

func TestVerifyNodeSignature_BadSignatureBytes(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Valid base64 but bogus signature bytes.
	bad := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if err := authz.VerifyNodeSignature(pub, "", map[string]interface{}{"signature": bad}, "challenge"); err == nil {
		t.Error("bad sig: want error")
	}
}

func TestVerifyHeartbeatSignature_DelegatesToVerifyNodeSignature(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	challenge := "hb:7"
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(challenge)))
	if err := authz.VerifyHeartbeatSignature(pub, "", map[string]interface{}{"signature": sigB64}, challenge); err != nil {
		t.Errorf("happy: %v", err)
	}
}
