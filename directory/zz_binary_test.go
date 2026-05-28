// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"net"
	"sync"
	"testing"
	"time"
)

// drainConn reads everything off conn until it closes — keeps the
// pipe end alive so write deadlines don't trigger.
func drainConn(t *testing.T, conn net.Conn) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	return done
}

func TestHandleBinaryHeartbeat_InvalidPayloadWritesError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	drainConn(t, cli)

	finished := make(chan struct{})
	go func() {
		st.HandleBinaryHeartbeat(srv, []byte{0x00, 0x01}) // too short
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryHeartbeat blocked")
	}
}

func TestHandleBinaryHeartbeat_UnknownNodeWritesError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	drainConn(t, cli)

	// Build a valid 70-byte heartbeat payload for node 9999 with
	// a zero signature — DecodeHeartbeatReq is happy, the unknown-node
	// path triggers.
	payload := make([]byte, 70)
	payload[2] = 0x27 // 9999 = 0x270F
	payload[3] = 0x0F

	finished := make(chan struct{})
	go func() {
		st.HandleBinaryHeartbeat(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryHeartbeat blocked")
	}
}

func TestHandleBinaryLookup_InvalidPayload(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	drainConn(t, cli)

	finished := make(chan struct{})
	go func() {
		st.HandleBinaryLookup(srv, []byte{0x00})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryLookup blocked")
	}
}

func TestHandleBinaryResolve_InvalidPayload(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	drainConn(t, cli)

	finished := make(chan struct{})
	go func() {
		st.HandleBinaryResolve(srv, []byte{0x00})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryResolve blocked")
	}
}

func TestHandleBinaryLookup_UnknownNodeWritesError(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	drainConn(t, cli)

	// Lookup payload is 4 bytes: uint32 node_id.
	payload := []byte{0x00, 0x00, 0x27, 0x0F} // 9999
	finished := make(chan struct{})
	go func() {
		st.HandleBinaryLookup(srv, payload)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryLookup blocked")
	}
}

// TestHandleBinaryHeartbeat_ConcurrentClientsDoNotInterleave is a smoke
// test for the per-conn write path under multiple goroutines.
func TestHandleBinaryHeartbeat_ConcurrentClientsDoNotInterleave(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	const N = 5
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv, cli := net.Pipe()
			defer srv.Close()
			defer cli.Close()
			done := drainConn(t, cli)
			st.HandleBinaryHeartbeat(srv, []byte{}) // too short → error path
			cli.Close()
			<-done
		}()
	}
	wg.Wait()
}
