// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// fakeNodeView is a minimal NodeView for unit tests. All methods return
// zero/empty values unless the test populates the internal map.
type fakeNodeView struct {
	nodes map[uint32]fakeNode
}

type fakeNode struct {
	pubKey      []byte
	keyMeta     KeyInfo
	networks    []uint16
	externalID  string
	owner       string
	badge       string
	badgeSig    string
	provider    string
	recCommit   string
	recProvider string
}

func (v *fakeNodeView) LookupNodeKey(id uint32) ([]byte, bool) {
	n, ok := v.nodes[id]
	if !ok {
		return nil, false
	}
	return n.pubKey, true
}
func (v *fakeNodeView) LookupNodeFull(id uint32) (pubKey []byte, keyMeta KeyInfo, networks []uint16, externalID, owner string, ok bool) {
	n, ok2 := v.nodes[id]
	if !ok2 {
		return nil, KeyInfo{}, nil, "", "", false
	}
	return n.pubKey, n.keyMeta, n.networks, n.externalID, n.owner, true
}
func (v *fakeNodeView) UpdateNodeKey(uint32, []byte, []byte, time.Time) (string, error) {
	return "", nil
}
func (v *fakeNodeView) UpdateNodeKeyExpiry(uint32, time.Time) (time.Time, bool) {
	return time.Time{}, false
}
func (v *fakeNodeView) UpdateNodeExternalID(uint32, string) (string, bool) {
	return "", false
}
func (v *fakeNodeView) NodeIsEnterprise(uint32) bool { return false }
func (v *fakeNodeView) AdminToken() string           { return "test-admin" }
func (v *fakeNodeView) CheckAdminToken(map[string]interface{}) error {
	return nil
}
func (v *fakeNodeView) VerifyHeartbeatSignature([]byte, string, map[string]interface{}, string) error {
	return nil
}
func (v *fakeNodeView) Now() time.Time { return time.Now() }

func (v *fakeNodeView) SubmitBadge(id uint32, badge, badgeSig, provider string, now time.Time) bool {
	n, ok := v.nodes[id]
	if !ok {
		return false
	}
	n.badge = badge
	n.badgeSig = badgeSig
	n.provider = provider
	v.nodes[id] = n
	return true
}

func (v *fakeNodeView) SetRecoveryEnrollment(id uint32, commitment, provider string) bool {
	n, ok := v.nodes[id]
	if !ok {
		return false
	}
	n.recCommit = commitment
	n.recProvider = provider
	v.nodes[id] = n
	return true
}

func (v *fakeNodeView) GetRecoveryEnrollment(id uint32) (commitment, provider string, ok bool) {
	n, exists := v.nodes[id]
	if !exists || n.recCommit == "" {
		return "", "", false
	}
	return n.recCommit, n.recProvider, true
}

func (v *fakeNodeView) ForceRotateKey(id uint32, newPubKey []byte, now time.Time) (string, error) {
	n, ok := v.nodes[id]
	if !ok {
		return "", fmt.Errorf("node %d not found", id)
	}
	oldPubKeyB64 := base64.StdEncoding.EncodeToString(n.pubKey)
	n.pubKey = newPubKey
	v.nodes[id] = n
	return oldPubKeyB64, nil
}

func newTestStore() *Store {
	return NewStore(&fakeNodeView{nodes: map[uint32]fakeNode{}}, Callbacks{
		Save:                func() {},
		Audit:               func(string, ...any) {},
		IncKeyRotations:     func() {},
		IncIDPVerifications: func() {},
		RecordWAL:           func(uint32, string, string) {},
		OnKeyRotated:        func(uint32, string, string) {},
	})
}

func TestNewStore_HasJwksCache(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	if st == nil {
		t.Fatal("NewStore returned nil")
	}
	if st.jwksCache == nil {
		t.Error("jwksCache should be initialized")
	}
}

func TestStore_WebhookURL_SetGetRoundtrip(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	if got := st.GetWebhookURL(); got != "" {
		t.Errorf("initial = %q, want empty", got)
	}
	st.SetWebhookURL("https://idp.example/verify")
	if got := st.GetWebhookURL(); got != "https://idp.example/verify" {
		t.Errorf("after Set = %q", got)
	}
	st.SetWebhookURL("")
	if got := st.GetWebhookURL(); got != "" {
		t.Errorf("after clear = %q", got)
	}
}

func TestStore_IDPConfig_SetGetClear(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	if got := st.GetIDPConfig(); got != nil {
		t.Errorf("initial = %v, want nil", got)
	}
	cfg := &wire.BlueprintIdentityProvider{URL: "https://idp/verify"}
	st.SetIDPConfig(cfg)
	if got := st.GetIDPConfig(); got == nil || got.URL != "https://idp/verify" {
		t.Errorf("after Set = %v", got)
	}
	// SetIDPConfig also propagates URL to identity webhook.
	if got := st.GetWebhookURL(); got != "https://idp/verify" {
		t.Errorf("webhook URL should match IDP URL: %q", got)
	}

	st.ClearIDPConfig()
	if got := st.GetIDPConfig(); got != nil {
		t.Errorf("after Clear = %v", got)
	}
	if got := st.GetWebhookURL(); got != "" {
		t.Errorf("webhook URL after Clear = %q", got)
	}
}

func TestStore_SetIDPConfig_NilDoesNotTouchWebhook(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	st.SetWebhookURL("https://manual")
	st.SetIDPConfig(nil) // nil cfg should not clobber the webhook URL
	if got := st.GetWebhookURL(); got != "https://manual" {
		t.Errorf("webhook URL after nil SetIDPConfig = %q", got)
	}
}

// TestStore_VerifyToken_NoWebhook returns ("", nil) on no-config.
func TestStore_VerifyToken_NoWebhook(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	got, err := st.VerifyToken("any-token")
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestStore_VerifyToken_EmptyTokenShortCircuits returns ("", nil) on empty.
func TestStore_VerifyToken_EmptyTokenShortCircuits(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	st.SetWebhookURL("https://idp/verify")
	got, err := st.VerifyToken("")
	if err != nil || got != "" {
		t.Errorf("empty token: got (%q, %v)", got, err)
	}
}

// TestStore_VerifyToken_HappyPath drives the full happy webhook flow.
func TestStore_VerifyToken_HappyPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "my-token" {
			http.Error(w, "wrong token", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verified":    true,
			"external_id": "user-42",
		})
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)

	got, err := st.VerifyToken("my-token")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got != "user-42" {
		t.Errorf("got %q, want user-42", got)
	}
}

// TestStore_VerifyToken_NotVerified covers the rejected-by-webhook branch.
func TestStore_VerifyToken_NotVerified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verified": false,
			"error":    "expired token",
		})
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	if _, err := st.VerifyToken("token"); err == nil {
		t.Error("expected error when webhook rejects")
	}
}

// TestStore_VerifyToken_VerifiedButEmptyID covers the empty-ID rejection.
func TestStore_VerifyToken_VerifiedButEmptyID(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"verified": true})
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	if _, err := st.VerifyToken("token"); err == nil {
		t.Error("expected error when external_id is empty")
	}
}

// TestStore_VerifyToken_BadStatus covers the non-200 branch.
func TestStore_VerifyToken_BadStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	if _, err := st.VerifyToken("token"); err == nil {
		t.Error("expected error on 500")
	}
}

// TestStore_VerifyToken_BadJSON covers the JSON-parse error branch.
func TestStore_VerifyToken_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	if _, err := st.VerifyToken("token"); err == nil {
		t.Error("expected JSON parse error")
	}
}

// TestStore_VerifyToken_UnreachableHost covers the http.Post error branch.
func TestStore_VerifyToken_UnreachableHost(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	// Point at a closed port — http.Post should fail.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close() // server closed → POST fails

	st.SetWebhookURL(addr)
	if _, err := st.VerifyToken("token"); err == nil {
		t.Error("expected POST failure on closed server")
	}
}

// TestJsonUint32_Helper covers the local jsonUint32 helper.
func TestJsonUint32_Helper(t *testing.T) {
	t.Parallel()
	if got := jsonUint32(map[string]interface{}{"k": float64(42)}, "k"); got != 42 {
		t.Errorf("got %d", got)
	}
	if got := jsonUint32(map[string]interface{}{}, "missing"); got != 0 {
		t.Errorf("missing: got %d", got)
	}
	if got := jsonUint32(map[string]interface{}{"k": "string"}, "k"); got != 0 {
		t.Errorf("non-float: got %d", got)
	}
}

// TestStore_SetIdentityWebhookSecret_GetRoundtrip (PILOT-240).
func TestStore_SetIdentityWebhookSecret_GetRoundtrip(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	if got := st.GetIdentityWebhookSecret(); got != "" {
		t.Errorf("initial = %q, want empty", got)
	}
	st.SetIdentityWebhookSecret("my-secret")
	if got := st.GetIdentityWebhookSecret(); got != "my-secret" {
		t.Errorf("after Set = %q", got)
	}
	st.SetIdentityWebhookSecret("")
	if got := st.GetIdentityWebhookSecret(); got != "" {
		t.Errorf("after clear = %q", got)
	}
}

// TestStore_VerifyToken_SignsRequest (PILOT-240).
func TestStore_VerifyToken_SignsRequest(t *testing.T) {
	t.Parallel()
	const secret = "my-secret"
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Pilot-Signature-256")
		respBody := []byte(`{"verified":true,"external_id":"user-42"}`)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(respBody)
		w.Header().Set("X-Pilot-Signature-256", hex.EncodeToString(mac.Sum(nil)))
		w.Write(respBody)
	}))
	defer srv.Close()

	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	st.SetIdentityWebhookSecret(secret)

	got, err := st.VerifyToken("my-token")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got != "user-42" {
		t.Errorf("got %q, want user-42", got)
	}
	if gotSig == "" {
		t.Fatal("X-Pilot-Signature-256 request header not set")
	}
	expectedBody, _ := json.Marshal(identityVerifyRequest{Token: "my-token"})
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(expectedBody)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotSig), []byte(want)) {
		t.Errorf("request HMAC mismatch: got %s, want %s", gotSig, want)
	}
}

// TestStore_VerifyToken_RejectsUnsignedResponse (PILOT-240).
func TestStore_VerifyToken_RejectsUnsignedResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"verified":true,"external_id":"user-42"}`))
	}))
	defer srv.Close()
	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	st.SetIdentityWebhookSecret("my-secret")
	if _, err := st.VerifyToken("my-token"); err == nil {
		t.Fatal("expected rejection when response is unsigned")
	}
}

// TestStore_VerifyToken_RejectsWrongSignature (PILOT-240).
func TestStore_VerifyToken_RejectsWrongSignature(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respBody := []byte(`{"verified":true,"external_id":"user-42"}`)
		w.Header().Set("X-Pilot-Signature-256", "deadbeef")
		w.Write(respBody)
	}))
	defer srv.Close()
	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	st.SetIdentityWebhookSecret("my-secret")
	if _, err := st.VerifyToken("my-token"); err == nil {
		t.Fatal("expected rejection when response signature mismatches")
	}
}

// TestStore_VerifyToken_NoSignatureWithoutSecret (PILOT-240): backward compat.
func TestStore_VerifyToken_NoSignatureWithoutSecret(t *testing.T) {
	t.Parallel()
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Pilot-Signature-256")
		w.Write([]byte(`{"verified":true,"external_id":"user-42"}`))
	}))
	defer srv.Close()
	st := newTestStore()
	st.SetWebhookURL(srv.URL)
	got, err := st.VerifyToken("my-token")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got != "user-42" || gotSig != "" {
		t.Errorf("got %q sig=%q, want user-42 sig empty", got, gotSig)
	}
}

// TestStore_VerifyToken_WithSecret_EmptyTokenShortCircuits (PILOT-240).
func TestStore_VerifyToken_WithSecret_EmptyTokenShortCircuits(t *testing.T) {
	t.Parallel()
	st := newTestStore()
	st.SetWebhookURL("https://idp/verify")
	st.SetIdentityWebhookSecret("my-secret")
	got, err := st.VerifyToken("")
	if err != nil || got != "" {
		t.Errorf("empty token with secret: got (%q, %v)", got, err)
	}
}
