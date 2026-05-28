// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
	"github.com/pilot-protocol/common/crypto"
)

// TestHandleBinaryLookup_HappyPath registers a node, then issues a binary
// lookup and confirms the handler runs through the encode branch.
func TestHandleBinaryLookup_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[101] = &NodeInfo{
		ID:        101,
		PublicKey: id.PublicKey,
		Public:    true,
		RealAddr:  "1.2.3.4:5",
	}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryLookup(srv, wire.EncodeLookupReq(101))
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryResolve_RequesterMissing exercises the requester-not-registered branch.
func TestHandleBinaryResolve_RequesterMissing(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	sig := make([]byte, 64)
	payload := wire.EncodeResolveReq(10, 999, sig)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryResolve(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryResolve_RequesterNoPubKey exercises the no-pubkey branch.
func TestHandleBinaryResolve_RequesterNoPubKey(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: nil}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	sig := make([]byte, 64)
	payload := wire.EncodeResolveReq(10, 42, sig)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryResolve(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryResolve_BadSig exercises the failed-signature branch.
func TestHandleBinaryResolve_BadSig(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: id.PublicKey}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	// Garbage signature → Verify returns false.
	sig := make([]byte, 64)
	payload := wire.EncodeResolveReq(10, 42, sig)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryResolve(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryResolve_HappyPath uses a real signature and a registered target node.
func TestHandleBinaryResolve_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[42] = &NodeInfo{ID: 42, PublicKey: id.PublicKey, Networks: []uint16{5}}
	st.nodes[10] = &NodeInfo{ID: 10, Public: true, RealAddr: "9.9.9.9:5"}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	// Construct a real signature on "resolve:42:10".
	sig := id.Sign([]byte("resolve:42:10"))
	payload := wire.EncodeResolveReq(10, 42, sig)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryResolve(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryHeartbeat_HappyPath drives the signature-verify success path.
func TestHandleBinaryHeartbeat_HappyPath(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.nodes[55] = &NodeInfo{ID: 55, PublicKey: id.PublicKey}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	sig := id.Sign([]byte("heartbeat:55"))
	payload := wire.EncodeHeartbeatReq(55, sig)
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryHeartbeat(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}

// TestHandleBinaryHeartbeat_NoPubkey exercises the "node has no public key" branch.
func TestHandleBinaryHeartbeat_NoPubkey(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	st.mu.Lock()
	st.nodes[55] = &NodeInfo{ID: 55, PublicKey: nil}
	st.mu.Unlock()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	drainConn(t, cli)

	payload := make([]byte, 70)
	payload[2] = 0x00
	payload[3] = 0x37 // 55
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryHeartbeat(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked")
	}
}
