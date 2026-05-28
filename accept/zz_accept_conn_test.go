// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDispatcher counts what it sees.
type fakeDispatcher struct {
	mu           sync.Mutex
	jsonMsgs     int
	binHeartbeat int
	binLookup    int
	binResolve   int
}

func (d *fakeDispatcher) HandleMessage(msg map[string]interface{}, _ string) (map[string]interface{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jsonMsgs++
	return map[string]interface{}{"type": "ok"}, nil
}
func (d *fakeDispatcher) HandleSubscribeReplication(net.Conn) {}
func (d *fakeDispatcher) HandleBinaryHeartbeat(_ net.Conn, _ []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binHeartbeat++
}
func (d *fakeDispatcher) HandleBinaryLookup(_ net.Conn, _ []byte, _ string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binLookup++
}
func (d *fakeDispatcher) HandleBinaryResolve(_ net.Conn, _ []byte, _ string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binResolve++
}
func (d *fakeDispatcher) ReplicationToken() string { return "" }
func (d *fakeDispatcher) AddRequest()              {}

func TestAcceptor_HandleConn_JSON_HappyPath(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	// Client sends a tiny JSON-framed message.
	body := []byte(`{"type":"ping"}`)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))

	go func() {
		a.handleConn(srv)
	}()
	if _, err := cli.Write(append(lenBuf[:], body...)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the reply length prefix + body.
	cli.SetReadDeadline(time.Now().Add(time.Second))
	var replyLen [4]byte
	if _, err := cli.Read(replyLen[:]); err != nil {
		t.Fatalf("read reply len: %v", err)
	}
	respLen := binary.BigEndian.Uint32(replyLen[:])
	resp := make([]byte, respLen)
	if _, err := cli.Read(resp); err != nil {
		t.Fatalf("read reply body: %v", err)
	}
	var reply map[string]interface{}
	if err := json.Unmarshal(resp, &reply); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reply["type"] != "ok" {
		t.Errorf("reply = %v", reply)
	}

	// Close the client to drain handleConn.
	cli.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.jsonMsgs == 0 {
		t.Error("dispatcher.HandleMessage never called")
	}
}

func TestAcceptor_HandleConn_BinaryUnsupportedVersion(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go a.handleConn(srv)

	// Send magic + bad version.
	pkt := append([]byte{}, byte(0x50), byte(0x49), byte(0x4C), byte(0x54))
	pkt = append(pkt, byte(99)) // unsupported version
	if _, err := cli.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Read whatever the server sent back.
	cli.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	_, _ = cli.Read(buf)
	cli.Close()
}

func TestAcceptor_HandleConn_PeekErrorClosesConn(t *testing.T) {
	t.Parallel()
	d := &fakeDispatcher{}
	a := NewAcceptor(100, d)

	srv, cli := net.Pipe()
	cli.Close() // immediately close so peek returns error
	// handleConn should exit quickly.
	done := make(chan struct{})
	go func() {
		a.handleConn(srv)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn blocked after peek error")
	}
}
