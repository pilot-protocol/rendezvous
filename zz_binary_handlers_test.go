// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"net"
	"testing"
	"time"
)

// pipeConnPair returns a connected net.Conn pair so binary handlers
// can drain their decode error into a real conn.
func pipeConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// TestServer_HandleBinaryHeartbeat_InvalidPayload drives the binary
// heartbeat dispatch shim — the directory handler will decode-error on
// a too-short payload and write an error frame back.
func TestServer_HandleBinaryHeartbeat_InvalidPayload(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")

	srv, cli := pipeConnPair(t)
	doneCh := make(chan struct{})
	go func() {
		s.HandleBinaryHeartbeat(srv, []byte{0x01, 0x02}) // too short
		close(doneCh)
	}()
	// Read whatever the handler emitted so the pipe doesn't block.
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryHeartbeat blocked")
	}
}

// TestServer_HandleBinaryLookup_InvalidPayload exercises the binary
// lookup decode-error path.
func TestServer_HandleBinaryLookup_InvalidPayload(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	srv, cli := pipeConnPair(t)

	doneCh := make(chan struct{})
	go func() {
		s.HandleBinaryLookup(srv, []byte{0x00}, "127.0.0.1:1")
		close(doneCh)
	}()
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryLookup blocked")
	}
}

// TestServer_HandleBinaryResolve_InvalidPayload covers the resolve
// decode-error path.
func TestServer_HandleBinaryResolve_InvalidPayload(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	srv, cli := pipeConnPair(t)

	doneCh := make(chan struct{})
	go func() {
		s.HandleBinaryResolve(srv, []byte{0x00}, "127.0.0.1:1")
		close(doneCh)
	}()
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBinaryResolve blocked")
	}
}
