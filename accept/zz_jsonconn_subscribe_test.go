// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// replDispatcher returns a configurable replication token and records the
// HandleSubscribeReplication invocation.
type replDispatcher struct {
	fakeDispatcher
	token       string
	subscribed  bool
	subscribeMu net.Conn
}

func (d *replDispatcher) ReplicationToken() string { return d.token }
func (d *replDispatcher) HandleSubscribeReplication(c net.Conn) {
	d.mu.Lock()
	d.subscribed = true
	d.subscribeMu = c
	d.mu.Unlock()
}

func writeJSONFrame(t *testing.T, c net.Conn, body []byte) {
	t.Helper()
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := c.Write(append(lenBuf[:], body...)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestJSONConn_SubscribeReplication_NoTokenConfiguredReturnsError(t *testing.T) {
	t.Parallel()
	d := &replDispatcher{token: ""}
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
		a.handleConn(srv)
		close(done)
	}()
	writeJSONFrame(t, cli, []byte(`{"type":"subscribe_replication"}`))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn blocked")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.subscribed {
		t.Error("subscribe should not run without a token")
	}
}

func TestJSONConn_SubscribeReplication_InvalidTokenReturnsError(t *testing.T) {
	t.Parallel()
	d := &replDispatcher{token: "secret"}
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
		a.handleConn(srv)
		close(done)
	}()
	writeJSONFrame(t, cli, []byte(`{"type":"subscribe_replication","token":"wrong"}`))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.subscribed {
		t.Error("subscribe should not run with invalid token")
	}
}

func TestJSONConn_SubscribeReplication_ValidTokenInvokesHandler(t *testing.T) {
	t.Parallel()
	d := &replDispatcher{token: "secret"}
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
		a.handleConn(srv)
		close(done)
	}()
	writeJSONFrame(t, cli, []byte(`{"type":"subscribe_replication","token":"secret"}`))
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	<-done

	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.subscribed {
		t.Error("subscribe handler should have been invoked")
	}
}
