// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"net"
	"testing"
	"time"
)

// --- verifyNodeSignature (delegate) -------------------------------------

func TestServer_VerifyNodeSignature_AdminTokenAllows(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	node := &NodeInfo{ID: 1, PublicKey: nil}
	// With no pubkey AND admin token in the message, authzpkg fast-paths
	// the call. We just exercise the wrapper.
	_ = s.verifyNodeSignature(node, map[string]interface{}{"admin_token": "admin"}, "ch")
}

func TestServer_VerifyHeartbeatSignature_Delegates(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	// Same shape — exercise the wrapper.
	_ = s.verifyHeartbeatSignature(nil, "admin", map[string]interface{}{"admin_token": "admin"}, "ch")
}

// --- SetStandby ---------------------------------------------------------

func TestServer_SetStandby_SetsFlag(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if s.IsStandby() {
		t.Fatal("fresh server should not be standby")
	}
	// SetStandby spawns a RunStandby goroutine. Pass an unroutable primary
	// so the goroutine fails fast; we just want to set the flag.
	s.SetStandby("127.0.0.1:1")
	if !s.IsStandby() {
		t.Fatal("flag not set")
	}
	// Allow background goroutine to attempt connection; not asserting its
	// outcome — it'll just error out repeatedly until t.Cleanup -> Close.
	time.Sleep(50 * time.Millisecond)
}

// --- HandleSubscribeReplication smoke -----------------------------------

func TestServer_HandleSubscribeReplication_NoAuthClosesConn(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// No replication token configured; HandleSubscribeReplication should
	// quickly reject + close. Use net.Pipe for synchronous semantics.
	srv, cli := net.Pipe()
	defer cli.Close()
	go func() {
		defer srv.Close()
		// Drain anything the server writes (an error response, maybe).
		buf := make([]byte, 4096)
		for {
			_ = srv.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := srv.Read(buf); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		s.HandleSubscribeReplication(cli)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		// Closing the conn from outside should unblock the handler.
		cli.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("HandleSubscribeReplication hung")
		}
	}
}

// --- AddRequest / ReplicationToken accessors ----------------------------

func TestServer_AddRequest_IncrementsCounter(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	before := s.requestCount.Load()
	s.AddRequest()
	s.AddRequest()
	after := s.requestCount.Load()
	if after-before != 2 {
		t.Fatalf("delta = %d, want 2", after-before)
	}
}

func TestServer_ReplicationToken_DefaultEmpty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.ReplicationToken(); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	s.SetReplicationToken("rt")
	if got := s.ReplicationToken(); got != "rt" {
		t.Fatalf("got %q", got)
	}
}

// --- handleGetWebhook / handleGetWebhookDLQ / handleGetAuditExport ------

func TestServer_HandleGetWebhook_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetWebhook(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin error")
	}
}

func TestServer_HandleGetWebhook_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	resp, err := s.handleGetWebhook(map[string]interface{}{"admin_token": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["enabled"]; !ok {
		t.Fatalf("missing enabled key: %+v", resp)
	}
}

func TestServer_HandleGetWebhookDLQ_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetWebhookDLQ(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin error")
	}
}

func TestServer_HandleGetWebhookDLQ_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	if _, err := s.handleGetWebhookDLQ(map[string]interface{}{"admin_token": "admin"}); err != nil {
		t.Fatal(err)
	}
}

func TestServer_HandleGetAuditExport_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetAuditExport(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin error")
	}
}

// --- handleGetProvisionStatus -------------------------------------------

func TestServer_HandleGetProvisionStatus_RequiresAdmin(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	_, err := s.handleGetProvisionStatus(map[string]interface{}{"admin_token": "wrong"})
	if err == nil {
		t.Fatal("expected admin error")
	}
}

func TestServer_HandleGetProvisionStatus_HappyPath(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "admin")
	s.mu.Lock()
	s.networks[5] = &NetworkInfo{ID: 5, Name: "ent-net", Enterprise: true, Members: []uint32{1, 2}}
	s.mu.Unlock()
	resp, err := s.handleGetProvisionStatus(map[string]interface{}{"admin_token": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["networks"]; !ok {
		t.Fatalf("missing networks: %+v", resp)
	}
}

// --- jsonUint helpers via handler dispatch ------------------------------

func TestServer_AddRequest_AndRequestCountSync(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.AddRequest()
	if s.requestCount.Load() < 1 {
		t.Fatal("counter did not advance")
	}
}

// --- NodeIsEnterprise ---------------------------------------------------

func TestServer_NodeIsEnterprise_Branches(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.networks[1] = &NetworkInfo{ID: 1, Enterprise: false}
	s.networks[2] = &NetworkInfo{ID: 2, Enterprise: true}
	s.nodes[10] = &NodeInfo{ID: 10, Networks: []uint16{1}}
	s.nodes[20] = &NodeInfo{ID: 20, Networks: []uint16{1, 2}}
	s.mu.Unlock()
	if got := s.NodeIsEnterprise(10); got {
		t.Error("node 10 should not be enterprise")
	}
	if got := s.NodeIsEnterprise(20); !got {
		t.Error("node 20 should be enterprise")
	}
	if got := s.NodeIsEnterprise(999); got {
		t.Error("unknown node should be false")
	}
}
