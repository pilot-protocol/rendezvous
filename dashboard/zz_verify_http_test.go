// SPDX-License-Identifier: AGPL-3.0-or-later

package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newVerifyMux mounts only the verification routes on a bare mux, mirroring
// how tests elsewhere in this package exercise single endpoints without the
// full Serve lifecycle. registerVerifyRoutes is the SAME registration Serve
// uses, so there is no shim to drift.
func newVerifyMux(cb Callbacks) (*Handler, *http.ServeMux) {
	h := NewHandler(cb)
	mux := http.NewServeMux()
	h.registerVerifyRoutes(mux)
	return h, mux
}

func verifyCallbacks(t *testing.T) Callbacks {
	t.Helper()
	cb := minimalCallbacks()
	cb.VerifyRequest = func(canonical, sigB64 string) interface{} {
		return map[string]interface{}{
			"valid":     true,
			"envelope":  canonical,
			"signature": sigB64,
		}
	}
	cb.VerifyKeys = func() []map[string]string {
		return []map[string]string{{
			"kid":        "vfy-v1",
			"algo":       "ed25519",
			"public_key": "AAAAC3NzaC1lZDI1NTE5AAAA",
		}}
	}
	return cb
}

func postVerify(mux *http.ServeMux, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestVerifyHTTPHappyPath: a well-formed POST reaches the callback and the
// callback's response is returned verbatim as JSON.
func TestVerifyHTTPHappyPath(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	rec := postVerify(mux, `{"envelope":"pilot-req-v1|deadbeef","signature":"c2ln"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["valid"] != true {
		t.Fatalf("valid = %v, want true", payload["valid"])
	}
	if payload["envelope"] != "pilot-req-v1|deadbeef" || payload["signature"] != "c2ln" {
		t.Fatalf("callback did not receive envelope/signature: %v", payload)
	}
}

// TestVerifyHTTPMethodNotAllowed: only POST is accepted on /api/v1/verify.
func TestVerifyHTTPMethodNotAllowed(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/verify", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", method, rec.Code)
		}
	}
}

// TestVerifyHTTPMalformedBody: junk JSON and missing fields both 400.
func TestVerifyHTTPMalformedBody(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	for _, body := range []string{"{not json", "{}", `{"envelope":"only"}`, `{"signature":"only"}`} {
		rec := postVerify(mux, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

// TestVerifyHTTPOversizedBody: bodies beyond the 8KB cap are rejected.
func TestVerifyHTTPOversizedBody(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	big := `{"envelope":"` + strings.Repeat("a", maxVerifyBodyBytes+1) + `","signature":"c2ln"}`
	rec := postVerify(mux, big)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status = %d, want 400 or 413", rec.Code)
	}
}

// TestVerifyHTTPBreakerOpen: an open dashboard.verify breaker turns both
// endpoints into 503s with the standard unavailable payload.
func TestVerifyHTTPBreakerOpen(t *testing.T) {
	t.Parallel()
	cb := verifyCallbacks(t)
	cb.BreakerAllow = func(name string) (bool, string) {
		if name == "dashboard.verify" {
			return false, "maintenance"
		}
		return true, ""
	}
	_, mux := newVerifyMux(cb)

	rec := postVerify(mux, `{"envelope":"e","signature":"s"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("verify with open breaker: status = %d, want 503", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal 503 body: %v", err)
	}
	if payload["status"] != "unavailable" || payload["reason"] != "maintenance" {
		t.Fatalf("503 payload = %v", payload)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/keys", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("keys with open breaker: status = %d, want 503", rec.Code)
	}
}

// TestVerifyHTTPRateLimit: the 61st request within a minute from one IP is
// rejected with 429; the verify limiter is independent of badgeLimiter.
func TestVerifyHTTPRateLimit(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	body := `{"envelope":"e","signature":"s"}`
	for i := 0; i < 60; i++ {
		rec := postVerify(mux, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}
	rec := postVerify(mux, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 61: status = %d, want 429", rec.Code)
	}
}

// TestVerifyHTTPKeys: GET returns the issuer key list; POST is a 405.
func TestVerifyHTTPKeys(t *testing.T) {
	t.Parallel()
	_, mux := newVerifyMux(verifyCallbacks(t))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Keys) != 1 {
		t.Fatalf("keys length = %d, want 1", len(payload.Keys))
	}
	k := payload.Keys[0]
	if k["kid"] != "vfy-v1" || k["algo"] != "ed25519" || k["public_key"] == "" {
		t.Fatalf("key entry = %v", k)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/verify/keys", bytes.NewReader(nil))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST keys: status = %d, want 405", rec.Code)
	}
}

// TestVerifyHTTPNoCallback: with no VerifyRequest wired the endpoint reports
// unavailability instead of panicking.
func TestVerifyHTTPNoCallback(t *testing.T) {
	t.Parallel()
	cb := verifyCallbacks(t)
	cb.VerifyRequest = nil
	_, mux := newVerifyMux(cb)

	rec := postVerify(mux, `{"envelope":"e","signature":"s"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
