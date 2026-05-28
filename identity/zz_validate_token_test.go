// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

func TestHandleValidateToken_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	_, err := st.HandleValidateToken(map[string]interface{}{"token": "x"})
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleValidateToken_EmptyTokenError(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleValidateToken(map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "token is required") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleValidateToken_NoIDPConfigured(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleValidateToken(map[string]interface{}{"token": "any-token"})
	if err == nil || !strings.Contains(err.Error(), "no identity provider") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleValidateToken_InvalidJWT(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{Type: "oidc", URL: "https://x", Issuer: "iss", ClientID: "aud"})
	_, err := st.HandleValidateToken(map[string]interface{}{"token": "not.a.jwt!"})
	if err == nil || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleValidateToken_HS256_HappyPath(t *testing.T) {
	t.Parallel()
	// Stand up a JWKS server returning an HS256 secret key.
	secret := []byte("supersecret")
	keyB64 := base64.RawURLEncoding.EncodeToString(secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"keys":[{"kid":"k1","kty":"oct","alg":"HS256","k":%q}]}`, keyB64)
	}))
	defer srv.Close()

	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{
		Type: "oidc", URL: srv.URL, Issuer: "https://issuer", ClientID: "my-aud",
	})

	// Build a valid HS256 JWT.
	header := map[string]any{"alg": "HS256", "kid": "k1"}
	claims := map[string]any{
		"iss": "https://issuer",
		"sub": "user-1",
		"aud": "my-aud",
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Hour).Unix(),
	}
	headerB, _ := json.Marshal(header)
	claimsB, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerB) + "." + base64.RawURLEncoding.EncodeToString(claimsB)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := signingInput + "." + sig

	resp, err := st.HandleValidateToken(map[string]interface{}{"token": token})
	if err != nil {
		t.Fatalf("HandleValidateToken: %v", err)
	}
	if resp["verified"] != true {
		t.Errorf("verified = %v, want true", resp["verified"])
	}
	if resp["subject"] != "user-1" {
		t.Errorf("subject = %v", resp["subject"])
	}
}

func TestHandleValidateToken_HS256_BadSignature(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	keyB64 := base64.RawURLEncoding.EncodeToString(secret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"keys":[{"kid":"k1","kty":"oct","alg":"HS256","k":%q}]}`, keyB64)
	}))
	defer srv.Close()

	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{
		Type: "oidc", URL: srv.URL, Issuer: "https://issuer", ClientID: "my-aud",
	})

	// Build a JWT with a bogus signature.
	header := map[string]any{"alg": "HS256", "kid": "k1"}
	claims := map[string]any{
		"iss": "https://issuer",
		"sub": "user-1",
		"aud": "my-aud",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	headerB, _ := json.Marshal(header)
	claimsB, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerB) + "." + base64.RawURLEncoding.EncodeToString(claimsB)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString([]byte("not-the-real-mac"))

	resp, err := st.HandleValidateToken(map[string]interface{}{"token": token})
	if err != nil {
		t.Fatalf("HandleValidateToken: %v", err)
	}
	if resp["verified"] != false {
		t.Errorf("verified = %v, want false", resp["verified"])
	}
}

func TestHandleValidateToken_UnsupportedAlg(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{
		Type: "oidc", URL: "https://x", Issuer: "iss", ClientID: "aud",
	})

	header := map[string]any{"alg": "none"}
	claims := map[string]any{
		"iss": "iss", "sub": "u", "aud": "aud", "exp": time.Now().Add(time.Hour).Unix(),
	}
	headerB, _ := json.Marshal(header)
	claimsB, _ := json.Marshal(claims)
	token := base64.RawURLEncoding.EncodeToString(headerB) + "." +
		base64.RawURLEncoding.EncodeToString(claimsB) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	_, err := st.HandleValidateToken(map[string]interface{}{"token": token})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err = %v", err)
	}
}

func TestHandleValidateToken_ClaimsValidationFailure(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{
		Type: "oidc", URL: "https://x", Issuer: "expected-iss", ClientID: "expected-aud",
	})

	header := map[string]any{"alg": "HS256", "kid": "k1"}
	// Issuer doesn't match → ValidateJWTClaims fails → verified=false response.
	claims := map[string]any{
		"iss": "wrong-iss",
		"sub": "u",
		"aud": "expected-aud",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	headerB, _ := json.Marshal(header)
	claimsB, _ := json.Marshal(claims)
	token := base64.RawURLEncoding.EncodeToString(headerB) + "." +
		base64.RawURLEncoding.EncodeToString(claimsB) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("sig"))

	resp, err := st.HandleValidateToken(map[string]interface{}{"token": token})
	if err != nil {
		t.Fatalf("HandleValidateToken: %v", err)
	}
	if resp["verified"] != false {
		t.Errorf("verified = %v, want false (issuer mismatch)", resp["verified"])
	}
}
