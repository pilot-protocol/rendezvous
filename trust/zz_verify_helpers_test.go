// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// --- jsonUint32 ---------------------------------------------------------

func TestJSONUint32_Coverage(t *testing.T) {
	t.Parallel()
	if got := jsonUint32(map[string]interface{}{"n": float64(7)}, "n"); got != 7 {
		t.Fatalf("got %d", got)
	}
	if got := jsonUint32(map[string]interface{}{}, "absent"); got != 0 {
		t.Fatalf("missing: %d", got)
	}
	if got := jsonUint32(map[string]interface{}{"n": float64(-1)}, "n"); got != 0 {
		t.Fatalf("negative: %d", got)
	}
	huge := float64(^uint32(0)) + 1
	if got := jsonUint32(map[string]interface{}{"n": huge}, "n"); got != 0 {
		t.Fatalf("overflow: %d", got)
	}
	if got := jsonUint32(map[string]interface{}{"n": "x"}, "n"); got != 0 {
		t.Fatalf("string: %d", got)
	}
}

// --- checkAdminToken ----------------------------------------------------

func TestCheckAdminToken_NoTokenConfigured(t *testing.T) {
	t.Parallel()
	err := checkAdminToken(map[string]interface{}{}, "")
	if err == nil || !strings.Contains(err.Error(), "no admin token configured") {
		t.Fatalf("%v", err)
	}
}

func TestCheckAdminToken_MismatchRejected(t *testing.T) {
	t.Parallel()
	err := checkAdminToken(map[string]interface{}{"admin_token": "wrong"}, "expected")
	if err == nil || !strings.Contains(err.Error(), "invalid admin token") {
		t.Fatalf("%v", err)
	}
}

func TestCheckAdminToken_MatchAllowed(t *testing.T) {
	t.Parallel()
	if err := checkAdminToken(map[string]interface{}{"admin_token": "ok"}, "ok"); err != nil {
		t.Fatal(err)
	}
}

// --- verifyHeartbeatSignature ------------------------------------------

func TestVerifyHeartbeatSignature_NoPubkeyFallsBackToAdmin(t *testing.T) {
	t.Parallel()
	if err := verifyHeartbeatSignature(nil, "admin", map[string]interface{}{"admin_token": "admin"}, "ch"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyHeartbeatSignature_NoPubkeyAdminMismatch(t *testing.T) {
	t.Parallel()
	err := verifyHeartbeatSignature(nil, "admin", map[string]interface{}{"admin_token": "wrong"}, "ch")
	if err == nil || !strings.Contains(err.Error(), "node has no public key") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyHeartbeatSignature_MissingSig(t *testing.T) {
	t.Parallel()
	pk := []byte("not-a-real-key-but-non-nil")
	err := verifyHeartbeatSignature(pk, "", map[string]interface{}{}, "ch")
	if err == nil || !strings.Contains(err.Error(), "signature required") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyHeartbeatSignature_BadBase64(t *testing.T) {
	t.Parallel()
	pk := []byte("not-real")
	err := verifyHeartbeatSignature(pk, "", map[string]interface{}{"signature": "!!!not-b64!!!"}, "ch")
	if err == nil || !strings.Contains(err.Error(), "invalid signature encoding") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyHeartbeatSignature_GoodSig(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sig := id.Sign([]byte("ch"))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if err := verifyHeartbeatSignature(id.PublicKey, "", map[string]interface{}{"signature": sigB64}, "ch"); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestVerifyHeartbeatSignature_WrongSig(t *testing.T) {
	t.Parallel()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Sign different challenge than what we'll verify against.
	sig := id.Sign([]byte("other"))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	err = verifyHeartbeatSignature(id.PublicKey, "", map[string]interface{}{"signature": sigB64}, "actual-challenge")
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("%v", err)
	}
}
