// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/pilot-protocol/common/crypto"
)

// TestHandshakeNotifierNamesTheRecipient: a relayed handshake request tells
// the notifier the target's node ID, the relayed answer tells it the
// original requester's, and a refused message tells it nothing.
func TestHandshakeNotifierNamesTheRecipient(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	var notified []uint32
	s.SetHandshakeNotifier(func(nodeID uint32) { notified = append(notified, nodeID) })

	register := func() (*crypto.Identity, uint32) {
		t.Helper()
		id, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := s.handleMessage(map[string]interface{}{
			"type":        "register",
			"listen_addr": "203.0.113.5:4000",
			"public_key":  crypto.EncodePublicKey(id.PublicKey),
		}, "203.0.113.5:50000")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		var nodeID uint32
		switch v := resp["node_id"].(type) {
		case uint32:
			nodeID = v
		case float64:
			nodeID = uint32(v)
		default:
			t.Fatalf("node_id has type %T", resp["node_id"])
		}
		return id, nodeID
	}
	sign := func(id *crypto.Identity, format string, a, b uint32) string {
		return base64.StdEncoding.EncodeToString(id.Sign([]byte(fmt.Sprintf(format, a, b))))
	}
	idA, a := register()
	idB, b := register()

	request := map[string]interface{}{
		"type":          "request_handshake",
		"from_node_id":  float64(a),
		"to_node_id":    float64(b),
		"justification": "hello",
		"signature":     sign(idA, "handshake:%d:%d", a, b),
	}
	if _, err := s.handleMessage(request, "203.0.113.5:50000"); err != nil {
		t.Fatalf("request_handshake: %v", err)
	}
	if len(notified) != 1 || notified[0] != b {
		t.Fatalf("after the request: notified %v, want [%d] (the target)", notified, b)
	}

	// The duplicate is refused; nothing new is waiting, so no notify.
	if _, err := s.handleMessage(request, "203.0.113.5:50000"); err == nil {
		t.Fatal("duplicate request accepted")
	}
	if len(notified) != 1 {
		t.Fatalf("refused request notified: %v", notified)
	}

	if _, err := s.handleMessage(map[string]interface{}{
		"type":      "respond_handshake",
		"node_id":   float64(b),
		"peer_id":   float64(a),
		"accept":    true,
		"signature": sign(idB, "respond:%d:%d", b, a),
	}, "203.0.113.5:50000"); err != nil {
		t.Fatalf("respond_handshake: %v", err)
	}
	if len(notified) != 2 || notified[1] != a {
		t.Fatalf("after the answer: notified %v, want [%d %d] (target, then requester)", notified, b, a)
	}
}
