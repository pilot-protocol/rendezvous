// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// writeBinaryFrame writes a wire frame to conn. Matches wire.WriteFrame
// but inline so the test doesn't need to round-trip through that helper.
func writeBinaryFrame(t *testing.T, c net.Conn, msgType byte, payload []byte) {
	t.Helper()
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(1+len(payload)))
	hdr[4] = msgType
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatalf("write hdr: %v", err)
	}
	if len(payload) > 0 {
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
}

func TestHandleBinaryConn_DispatchesHeartbeat(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()

	// Send a heartbeat frame — payload doesn't need to be valid, the
	// dispatcher fake just counts it.
	writeBinaryFrame(t, cli, wire.MsgHeartbeat, []byte("ignored"))
	time.Sleep(50 * time.Millisecond)
	cli.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleBinaryConn blocked")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.binHeartbeat != 1 {
		t.Errorf("binHeartbeat = %d, want 1", d.binHeartbeat)
	}
}

func TestHandleBinaryConn_DispatchesLookup(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()
	writeBinaryFrame(t, cli, wire.MsgLookup, []byte("ignored"))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.binLookup != 1 {
		t.Errorf("binLookup = %d, want 1", d.binLookup)
	}
}

func TestHandleBinaryConn_DispatchesResolve(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()
	writeBinaryFrame(t, cli, wire.MsgResolve, []byte("ignored"))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.binResolve != 1 {
		t.Errorf("binResolve = %d, want 1", d.binResolve)
	}
}

func TestHandleBinaryConn_UnknownMessageType(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	// Drain client side so the server's error frame doesn't block.
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()
	writeBinaryFrame(t, cli, byte(0x77), []byte{})
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done
}

func TestHandleBinaryConn_JSONFallback_DispatchesToHandleMessage(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	// Drain client side.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()

	// Send a JSON frame: type=0x00, payload is a small JSON message.
	writeBinaryFrame(t, cli, wire.MsgJSON, []byte(`{"type":"hello"}`))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.jsonMsgs != 1 {
		t.Errorf("jsonMsgs = %d, want 1", d.jsonMsgs)
	}
}

func TestHandleBinaryConn_JSONFallback_BadJSON(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()
	writeBinaryFrame(t, cli, wire.MsgJSON, []byte("not json"))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done
}

func TestHandleBinaryConn_JSONFallback_RejectsSubscribeReplication(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := cli.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		a.handleBinaryConn(srv)
		close(done)
	}()
	writeBinaryFrame(t, cli, wire.MsgJSON, []byte(`{"type":"subscribe_replication"}`))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done
}
