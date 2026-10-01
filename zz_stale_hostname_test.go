// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// These tests pin what the registry does for a node that vanished without
// deregistering: its owner binding and its hostname are held until it is
// reaped (or an operator deregisters it), and resolve_hostname reports how
// long ago it was last seen so callers can tell a silent holder from a live
// one. Claimability is deliberately not tied to liveness — a node that is
// briefly offline must not lose its name to whoever asks first.

func evRegister(t *testing.T, s *Server, id *crypto.Identity, owner, hostname string) map[string]interface{} {
	t.Helper()
	resp, err := s.handleMessage(map[string]interface{}{
		"type":        "register",
		"listen_addr": "198.51.100.7:4000",
		"public_key":  crypto.EncodePublicKey(id.PublicKey),
		"owner":       owner,
		"hostname":    hostname,
	}, "198.51.100.7:4000")
	if err != nil {
		t.Fatalf("register(owner=%q hostname=%q): %v", owner, hostname, err)
	}
	return resp
}

func evIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func evAge(s *Server, nodeID uint32, d time.Duration) {
	s.mu.Lock()
	s.nodes[nodeID].SetLastSeen(time.Now().Add(-d))
	s.mu.Unlock()
}

// Same -email, fresh key: refused while the old record exists. This is the
// H2/H3 guard (directory.go owner-based reclaim) and is intended.
func TestLostIdentitySameOwnerRefused(t *testing.T) {
	s := newTestServer(t, "admin")
	old := evRegister(t, s, evIdentity(t), "n1@lab.test", "n1")
	oldID := old["node_id"].(uint32)
	evAge(s, oldID, 10*time.Minute) // gone, not yet reaped

	_, err := s.handleMessage(map[string]interface{}{
		"type":        "register",
		"listen_addr": "198.51.100.8:4000",
		"public_key":  crypto.EncodePublicKey(evIdentity(t).PublicKey),
		"owner":       "n1@lab.test",
		"hostname":    "n1",
	}, "198.51.100.8:4000")
	if err == nil || !strings.Contains(err.Error(), "use recover_identity to rotate the key") {
		t.Fatalf("want owner-rebind refusal, got %v", err)
	}
}

// New email, fresh key, old hostname. The holder
// has been silent for 10 minutes (ten missed 60s heartbeats) and is not yet
// reaped (30m). The name is unclaimable by register and by set_hostname, and
// resolve_hostname answers with the silent node plus the time it was last
// seen.
func TestStaleHolderKeepsHostnameUntilReap(t *testing.T) {
	s := newTestServer(t, "admin")
	old := evRegister(t, s, evIdentity(t), "n1@lab.test", "n1")
	oldID := old["node_id"].(uint32)
	s.mu.Lock()
	s.nodes[oldID].Public = true
	s.mu.Unlock()
	evAge(s, oldID, 10*time.Minute)

	fresh := evIdentity(t)
	reg := evRegister(t, s, fresh, "n1-new@lab.test", "n1")
	freshID := reg["node_id"].(uint32)
	if he, _ := reg["hostname_error"].(string); !strings.Contains(he, "already in use") {
		t.Fatalf("register: want hostname_error, got resp=%v", reg)
	}

	_, err := s.handleMessage(map[string]interface{}{
		"type": "set_hostname", "node_id": float64(freshID), "hostname": "n1",
		"signature": base64.StdEncoding.EncodeToString(fresh.Sign([]byte("set_hostname:" + itoa(freshID)))),
	}, "")
	if err == nil || !strings.Contains(err.Error(), `hostname "n1" already in use by node`) {
		t.Fatalf("set_hostname: want in-use refusal, got %v", err)
	}

	res, err := s.handleMessage(map[string]interface{}{"type": "resolve_hostname", "hostname": "n1"}, "")
	if err != nil {
		t.Fatalf("resolve_hostname: %v", err)
	}
	if res["node_id"].(uint32) != oldID {
		t.Fatalf("resolve_hostname: want dead node %d, got %v", oldID, res["node_id"])
	}
	ls, ok := res["last_seen_unix"].(int64)
	if !ok {
		t.Fatalf("resolve_hostname: last_seen_unix missing or mistyped: %#v", res["last_seen_unix"])
	}
	if ago := time.Now().Unix() - ls; ago < 9*60 || ago > 11*60 {
		t.Fatalf("resolve_hostname: last_seen_unix is %ds ago, want ~600s", ago)
	}

	// Past the reap threshold the name is released to whoever asks first.
	evAge(s, oldID, 31*time.Minute)
	s.Reap()
	if _, err := s.handleMessage(map[string]interface{}{
		"type": "set_hostname", "node_id": float64(freshID), "hostname": "n1",
		"signature": base64.StdEncoding.EncodeToString(fresh.Sign([]byte("set_hostname:" + itoa(freshID)))),
	}, ""); err != nil {
		t.Fatalf("set_hostname after reap: %v", err)
	}
}

// The operator remedy: an admin-token deregister of the
// dead node frees the hostname immediately.
func TestAdminDeregisterFreesHostname(t *testing.T) {
	s := newTestServer(t, "admin")
	old := evRegister(t, s, evIdentity(t), "n1@lab.test", "n1")
	oldID := old["node_id"].(uint32)
	evAge(s, oldID, 10*time.Minute)

	if _, err := s.handleMessage(map[string]interface{}{
		"type": "deregister", "node_id": float64(oldID), "admin_token": "admin",
	}, ""); err != nil {
		t.Fatalf("admin deregister: %v", err)
	}
	reg := evRegister(t, s, evIdentity(t), "n1-new@lab.test", "n1")
	if reg["hostname"] != "n1" {
		t.Fatalf("hostname not claimable after admin deregister: %v", reg)
	}
}

// A live holder reports a current last_seen_unix, on the public path and on
// the authorized private path alike; a refused private resolve leaks nothing.
func TestResolveHostnameLastSeenUnix(t *testing.T) {
	s := newTestServer(t, "admin")
	holder := evRegister(t, s, evIdentity(t), "", "svc")
	holderID := holder["node_id"].(uint32)
	peer := evRegister(t, s, evIdentity(t), "", "")
	peerID := peer["node_id"].(uint32)
	now := time.Now().Unix()

	// Private holder, stranger asking: indistinguishable from not found.
	if _, err := s.handleMessage(map[string]interface{}{
		"type": "resolve_hostname", "hostname": "svc", "requester_id": float64(peerID),
	}, ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("private resolve by a stranger: err=%v", err)
	}

	// Private holder, asking for itself.
	res, err := s.handleMessage(map[string]interface{}{
		"type": "resolve_hostname", "hostname": "svc", "requester_id": float64(holderID),
	}, "")
	if err != nil {
		t.Fatalf("private resolve by the holder: %v", err)
	}
	if ls, ok := res["last_seen_unix"].(int64); !ok || ls < now-5 || ls > now+5 {
		t.Fatalf("private path: last_seen_unix=%#v, want ~%d", res["last_seen_unix"], now)
	}

	// Public holder, anonymous asking.
	s.mu.Lock()
	s.nodes[holderID].Public = true
	s.mu.Unlock()
	res, err = s.handleMessage(map[string]interface{}{"type": "resolve_hostname", "hostname": "svc"}, "")
	if err != nil {
		t.Fatalf("public resolve: %v", err)
	}
	if ls, ok := res["last_seen_unix"].(int64); !ok || ls < now-5 || ls > now+5 {
		t.Fatalf("public path: last_seen_unix=%#v, want ~%d", res["last_seen_unix"], now)
	}
	for _, k := range []string{"type", "node_id", "address", "public", "hostname"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("existing field %q missing from resolve_hostname_ok", k)
		}
	}
}

func itoa(v uint32) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}
