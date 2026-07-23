// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/common/registry/wire"
)

func readWireFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	msgType, payload, err := wire.ReadFrame(conn)
	if err != nil {
		t.Fatalf("wire.ReadFrame: %v", err)
	}
	return msgType, payload
}

func TestHandleLookup_StrictOff_PrivateNodeFullyDisclosed(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{
		ID: 42, PublicKey: id.PublicKey, Public: false,
		Networks: []uint16{5}, Hostname: "priv", ExternalID: "ext-1",
	}
	st.mu.Unlock()

	resp, err := st.HandleLookup(map[string]interface{}{"node_id": float64(42)})
	if err != nil {
		t.Fatalf("expected legacy behavior to disclose private node with no requester, got err: %v", err)
	}
	if resp["hostname"] != "priv" {
		t.Fatalf("expected hostname disclosed under flag-off, resp=%v", resp)
	}
	if resp["external_id"] != "ext-1" {
		t.Fatalf("expected external_id disclosed under flag-off, resp=%v", resp)
	}
}

func TestHandleLookup_StrictOn_PrivateNodeDeniedToStranger(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }

	targetKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	strangerKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: targetKey.PublicKey, Public: false, Networks: []uint16{5}, Hostname: "priv"}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: strangerKey.PublicKey, Networks: []uint16{6}}
	st.mu.Unlock()

	_, err = st.HandleLookup(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected strict mode to deny an unauthorized stranger")
	}
	want := fmt.Errorf("node %d: %w", 42, protocol.ErrNodeNotFound).Error()
	if err.Error() != want {
		t.Fatalf("private-denied error must be byte-identical to the not-found error for the same node_id: got %q want %q", err.Error(), want)
	}
}

func TestHandleLookup_StrictOn_PrivateNodeAllowedBySharedNetwork(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }

	targetKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: targetKey.PublicKey, Public: false, Networks: []uint16{5, 8}, Hostname: "priv", ExternalID: "ext-1"}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: peerKey.PublicKey, Networks: []uint16{7, 8}}
	st.mu.Unlock()

	resp, err := st.HandleLookup(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err != nil {
		t.Fatalf("expected shared-network requester to be authorized, got: %v", err)
	}
	if resp["hostname"] != "priv" || resp["external_id"] != "ext-1" {
		t.Fatalf("authorized caller should see full identity fields, resp=%v", resp)
	}
}

func TestHandleLookup_StrictOn_PrivateNodeAllowedByTrust(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }
	st.cb.IsTrusted = func(a, b uint32) bool { return true }

	targetKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: targetKey.PublicKey, Public: false, Hostname: "priv"}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: peerKey.PublicKey}
	st.mu.Unlock()

	resp, err := st.HandleLookup(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err != nil {
		t.Fatalf("expected mutually trusted requester to be authorized, got: %v", err)
	}
	if resp["hostname"] != "priv" {
		t.Fatalf("resp=%v", resp)
	}
}

func TestHandleLookup_StrictOn_BadSignatureDenied(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }
	st.cb.IsTrusted = func(a, b uint32) bool { return true }
	st.cb.VerifyNodeSignature = func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
		return errBadSignature
	}

	targetKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: targetKey.PublicKey, Public: false}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: peerKey.PublicKey}
	st.mu.Unlock()

	_, err = st.HandleLookup(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected a failing signature check to deny access even though IsTrusted returns true")
	}
}

func TestHandleBinaryLookup_StrictOn_PrivateNodeDenied(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: id.PublicKey, Public: false}
	st.mu.Unlock()

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	var msgType byte
	var payload []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		msgType, payload = readWireFrame(t, cli)
	}()

	st.HandleBinaryLookup(srv, wire.EncodeLookupReq(42))

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked waiting for response frame")
	}
	if msgType != wire.MsgError {
		t.Fatalf("expected MsgError for a private node under strict mode, got msgType=%x", msgType)
	}
	got := wire.DecodeError(payload)
	want := "node 42: not found"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestHandleBinaryLookup_StrictOff_PrivateNodeStillDisclosed(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: id.PublicKey, Public: false}
	st.mu.Unlock()

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	var msgType byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		msgType, _ = readWireFrame(t, cli)
	}()

	st.HandleBinaryLookup(srv, wire.EncodeLookupReq(42))

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked waiting for response frame")
	}
	if msgType != wire.MsgLookupOK {
		t.Fatalf("expected legacy behavior (MsgLookupOK) for a private node with flag off, got msgType=%x", msgType)
	}
}

func TestHandleResolve_StrictOff_ErrorTextDistinguishesPrivate(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	requesterKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Public: false, Networks: []uint16{5}}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: requesterKey.PublicKey, Networks: []uint16{6}}
	st.mu.Unlock()

	_, err = st.HandleResolve(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected resolve denied for unauthorized requester")
	}
	want := "resolve denied: node 42 is private (establish mutual trust first)"
	if err.Error() != want {
		t.Fatalf("flag-off behavior changed: got %q want %q", err.Error(), want)
	}
}

func TestHandleResolve_StrictOn_ErrorUnifiedWithNotFound(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }
	requesterKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Public: false, Networks: []uint16{5}}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: requesterKey.PublicKey, Networks: []uint16{6}}
	st.mu.Unlock()

	_, err = st.HandleResolve(map[string]interface{}{
		"node_id":      float64(42),
		"requester_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected resolve denied for unauthorized requester")
	}
	want := fmt.Errorf("node %d: %w", 42, protocol.ErrNodeNotFound).Error()
	if err.Error() != want {
		t.Fatalf("private-denied error must be byte-identical to the not-found error for the same node_id under strict mode: got %q want %q", err.Error(), want)
	}
}

func TestHandleBinaryResolve_StrictOn_ErrorUnifiedWithNotFound(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: id.PublicKey, Public: false, Networks: []uint16{5}}
	st.nodes[10] = &NodeInfo{ID: 10, PublicKey: id.PublicKey, Networks: []uint16{6}}
	st.mu.Unlock()

	sig := id.Sign([]byte("resolve:10:42"))

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	var payload []byte
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, payload = readWireFrame(t, cli)
	}()
	st.HandleBinaryResolve(srv, wire.EncodeResolveReq(42, 10, sig))
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
	got := wire.DecodeError(payload)
	want := "node 42: not found"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestHandleResolveHostname_StrictOn_RequiresVerifiedSignature(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.cb.StrictDirectoryAuth = func() bool { return true }
	st.cb.VerifyNodeSignature = func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
		return errBadSignature
	}

	peerKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "priv", Public: false}
	st.nodes[99] = &NodeInfo{ID: 99, PublicKey: peerKey.PublicKey}
	st.hostnameIdx["priv"] = 42
	st.mu.Unlock()

	_, err = st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "priv",
		"requester_id": float64(99),
	})
	if err == nil {
		t.Fatal("expected strict mode to require a verified signature over requester_id")
	}
}

func TestHandleResolveHostname_StrictOff_SpoofableRequesterStillWorks(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, Hostname: "self", Public: false}
	st.hostnameIdx["self"] = 42
	st.mu.Unlock()

	resp, err := st.HandleResolveHostname(map[string]interface{}{
		"hostname":     "self",
		"requester_id": float64(42),
	})
	if err != nil {
		t.Fatalf("legacy behavior must be unchanged with flag off: %v", err)
	}
	if resp["node_id"].(uint32) != 42 {
		t.Fatalf("resp=%v", resp)
	}
}

func TestHandleListNodes_StrictOn_RequiresMembership(t *testing.T) {
	t.Parallel()
	st := newStrictListNodesTestStore(t, 7, []uint32{100})
	st.cb.StrictDirectoryAuth = func() bool { return true }

	requesterKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[200] = &NodeInfo{ID: 200, PublicKey: requesterKey.PublicKey}
	st.mu.Unlock()

	_, err = st.HandleListNodes(
		map[string]interface{}{"network_id": float64(7), "requester_id": float64(200)},
		func(msg map[string]interface{}) error { return errAdminRequired },
	)
	if err == nil {
		t.Fatal("expected non-member requester to be denied under strict mode")
	}
}

func TestHandleListNodes_StrictOn_MemberAllowed(t *testing.T) {
	t.Parallel()
	st := newStrictListNodesTestStore(t, 7, []uint32{100})
	st.cb.StrictDirectoryAuth = func() bool { return true }

	requesterKey, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[100] = &NodeInfo{ID: 100, PublicKey: requesterKey.PublicKey}
	st.mu.Unlock()

	_, err = st.HandleListNodes(
		map[string]interface{}{"network_id": float64(7), "requester_id": float64(100)},
		func(msg map[string]interface{}) error { return errAdminRequired },
	)
	if err != nil {
		t.Fatalf("expected member requester to be allowed, got: %v", err)
	}
}

func TestHandleListNodes_StrictOff_NoMembershipRequired(t *testing.T) {
	t.Parallel()
	st := newStrictListNodesTestStore(t, 7, []uint32{100})

	_, err := st.HandleListNodes(
		map[string]interface{}{"network_id": float64(7)},
		func(msg map[string]interface{}) error { return errAdminRequired },
	)
	if err != nil {
		t.Fatalf("flag-off behavior must not require membership: %v", err)
	}
}

var (
	errBadSignature  = &testErr{"signature verification failed"}
	errAdminRequired = &testErr{"no admin token configured"}
)

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }

func newStrictListNodesTestStore(t *testing.T, netID uint16, members []uint32) *Store {
	t.Helper()

	nodes := make(map[uint32]*NodeInfo)
	pubKeyIdx := make(map[string]uint32)
	ownerIdx := make(map[string]uint32)
	hostnameIdx := make(map[string]uint32)
	nextNode := uint32(1)
	maxNodes := 0
	reapCursor := uint32(0)
	listNodesCache := &ListNodesCacheState{}
	listNodesCache.Cond = sync.NewCond(&listNodesCache.Mu)
	listNodesPerNet := make(map[uint16]*ListNodesCacheState)
	var mu sync.RWMutex
	var shards NodeShards
	var perNetMu sync.Mutex

	cb := Callbacks{
		Save:  func() {},
		Audit: func(action string, attrs ...any) {},
		RecordWALRegister: func(nodeID uint32, owner, pubKeyB64, realAddr, hostname string, lanAddrs []string, version, createdAt string) {
		},
		RecordWALDeregister:           func(nodeID uint32) {},
		InvalidateListNodesCache:      func(netID uint16) {},
		InvalidateAdminListNodesCache: func() {},
		PublishMembershipChanged:      func(netID uint16) {},
		RemoveFromNetworks:            func(nodeID uint32, networks []uint16) []uint16 { return nil },
		ClearInviteInbox:              func(nodeID uint32) {},
		RequireAdminToken:             func(msg map[string]interface{}) error { return errAdminRequired },
		RequireAdminTokenLocked:       func(msg map[string]interface{}) error { return errAdminRequired },
		AdminToken:                    func() string { return "test-admin" },
		VerifyNodeSignature: func(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
			return nil
		},
		IsTrusted:              func(nodeA, nodeB uint32) bool { return false },
		BeaconAddr:             func() string { return "beacon:9001" },
		IncRegistrations:       func() {},
		IncDeregistrations:     func() {},
		IncRequestsTotal:       func(label string) {},
		IncErrorsTotal:         func(label string) {},
		ObserveRequestDuration: func(label string, seconds float64) {},
		Now:                    time.Now,
		AddNodeToBackbone:      func(nodeID uint32) {},
		ScanNetworkMemberships: func(nodeID uint32) []uint16 { return nil },
	}

	return NewStore(
		&mu,
		&shards,
		nodes,
		pubKeyIdx,
		ownerIdx,
		hostnameIdx,
		&nextNode,
		&maxNodes,
		&reapCursor,
		listNodesCache,
		&perNetMu,
		&listNodesPerNet,
		func(nid uint16) (NetworkMemberView, bool) {
			if nid != netID {
				return NetworkMemberView{}, false
			}
			return NetworkMemberView{Members: members}, true
		},
		cb,
	)
}
