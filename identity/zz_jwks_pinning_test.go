// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testJWKSBody = `{"keys":[{"kty":"oct","kid":"k1","k":"c2VjcmV0"}]}`

func newTLSJWKSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testJWKSBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func leafCert(t *testing.T, srv *httptest.Server) *x509.Certificate {
	t.Helper()
	if srv.TLS == nil || len(srv.TLS.Certificates) == 0 || len(srv.TLS.Certificates[0].Certificate) == 0 {
		t.Fatal("test server has no TLS leaf certificate")
	}
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert
}

// trustServer returns a fetch helper that trusts the test server's self-signed
// CA, so that the test exercises the PIN check on top of a passing chain
// verification rather than failing on the chain itself.
func fetchWithPin(t *testing.T, srv *httptest.Server, pin string) ([]JwksKey, error) {
	t.Helper()
	client := jwksPinnedHTTPClient(pin)
	tr := client.Transport.(*http.Transport)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.TLSClientConfig.RootCAs = pool
	return fetchJWKSKeysWithClient(srv.URL, client)
}

func TestJWKSPinning_SPKIMatchAccepts(t *testing.T) {
	srv := newTLSJWKSServer(t)
	pin := spkiFingerprint(leafCert(t, srv))

	keys, err := fetchWithPin(t, srv, pin)
	if err != nil {
		t.Fatalf("expected fetch to succeed with matching SPKI pin, got: %v", err)
	}
	if len(keys) != 1 || keys[0].Kid != "k1" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
}

func TestJWKSPinning_CertFingerprintMatchAccepts(t *testing.T) {
	srv := newTLSJWKSServer(t)
	cert := leafCert(t, srv)
	sum := sha256.Sum256(cert.Raw)
	pin := strings.ToUpper(hex.EncodeToString(sum[:])) // also checks case-insensitivity

	keys, err := fetchWithPin(t, srv, pin)
	if err != nil {
		t.Fatalf("expected fetch to succeed with matching cert pin, got: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("unexpected keys: %+v", keys)
	}
}

func TestJWKSPinning_MismatchRejected(t *testing.T) {
	srv := newTLSJWKSServer(t)
	wrongPin := strings.Repeat("ab", 32) // 64 hex chars, not the server's cert

	_, err := fetchWithPin(t, srv, wrongPin)
	if err == nil {
		t.Fatal("expected fetch to fail when pin does not match presented cert")
	}
	if !strings.Contains(err.Error(), "fetch JWKS") {
		t.Fatalf("expected transport-level failure, got: %v", err)
	}
}

func TestJWKSPinning_EmptyPinUsesSharedClient(t *testing.T) {
	if jwksPinnedHTTPClient("") != jwksHTTPClient {
		t.Fatal("empty pin should return the shared non-pinning client")
	}
}

func TestPinVerifyConnection_NoPeerCert(t *testing.T) {
	// VerifyConnection with no peer certificates must fail closed.
	err := pinVerifyConnection(strings.Repeat("00", 32))(tls.ConnectionState{})
	if err == nil {
		t.Fatal("expected error when no peer certificate is presented")
	}
}
