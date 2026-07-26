// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// setKeyExpiryReq builds a set_key_expiry message for the given node and
// expiry, signed over challenge.
func setKeyExpiryReq(id *crypto.Identity, nodeID uint32, expiresAt, challenge string) map[string]interface{} {
	return map[string]interface{}{
		"node_id":    float64(nodeID),
		"expires_at": expiresAt,
		"signature":  base64.StdEncoding.EncodeToString(id.Sign([]byte(challenge))),
	}
}

// TestSetKeyExpiryBindingRejectsSubstitutedValue pins the gated
// behaviour: with binding on, a signature is good only for the expiry it
// was produced for. Without it, the challenge covers the node id alone,
// so one captured signature authorizes any expiry for that node —
// including pushing it far enough out that the key never expires.
func TestSetKeyExpiryBindingRejectsSubstitutedValue(t *testing.T) {
	t.Parallel()
	const nodeID = uint32(1180)
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, nodeID, "alice")
	seedEnterpriseNetwork(t, s, 60, nodeID)

	soon := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	distant := time.Now().Add(9 * 365 * 24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)

	s.SetStrictExpiryBinding(true)
	if !s.StrictExpiryBinding() {
		t.Fatal("SetStrictExpiryBinding(true) did not take effect")
	}

	bound := fmt.Sprintf("set_key_expiry:%d:%s", nodeID, soon)

	// The signature matches the value it was made for.
	if _, err := s.identity.HandleSetKeyExpiry(setKeyExpiryReq(id, nodeID, soon, bound)); err != nil {
		t.Fatalf("request signed for its own expiry rejected: %v", err)
	}

	// Same signature, different expiry: the challenge no longer matches.
	substituted := setKeyExpiryReq(id, nodeID, soon, bound)
	substituted["expires_at"] = distant
	if _, err := s.identity.HandleSetKeyExpiry(substituted); err == nil {
		t.Fatal("a signature produced for one expiry authorized a different one")
	}
}

// TestSetKeyExpiryBindingDefaultsOff pins that the challenge is
// unchanged by default, so clients signing the original form keep
// working until an operator turns binding on.
func TestSetKeyExpiryBindingDefaultsOff(t *testing.T) {
	t.Parallel()
	const nodeID = uint32(1181)
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, nodeID, "bob")
	seedEnterpriseNetwork(t, s, 61, nodeID)

	if s.StrictExpiryBinding() {
		t.Fatal("expiry binding is on by default; it must be opt-in")
	}

	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	unbound := fmt.Sprintf("set_key_expiry:%d", nodeID)
	resp, err := s.identity.HandleSetKeyExpiry(setKeyExpiryReq(id, nodeID, expires, unbound))
	if err != nil {
		t.Fatalf("request signed with the original challenge rejected: %v", err)
	}
	if resp["type"] != "set_key_expiry_ok" {
		t.Fatalf("resp = %v; want set_key_expiry_ok", resp)
	}
}

// TestSetKeyExpiryBindingRejectsOldChallengeWhenOn pins that turning the
// gate on actually changes what must be signed, so a rollout that flips
// it before clients are updated fails loudly rather than silently
// accepting the old form.
func TestSetKeyExpiryBindingRejectsOldChallengeWhenOn(t *testing.T) {
	t.Parallel()
	const nodeID = uint32(1182)
	s := newTestServer(t, "")
	id, _ := seedNodeWithIdentity(t, s, nodeID, "carol")
	seedEnterpriseNetwork(t, s, 62, nodeID)
	s.SetStrictExpiryBinding(true)

	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	unbound := fmt.Sprintf("set_key_expiry:%d", nodeID)
	if _, err := s.identity.HandleSetKeyExpiry(setKeyExpiryReq(id, nodeID, expires, unbound)); err == nil {
		t.Fatal("a request signed with the unbound challenge was accepted while binding is enforced")
	}
}
