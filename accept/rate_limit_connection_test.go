package accept

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// Exercise both real dispatch loops beyond their grace period. Once capacity
// returns the next request must succeed on the same connection, and rejected
// requests must never reach the dispatcher.
func TestRateLimitKeepsConnection(t *testing.T) {
	for _, binary := range []bool{false, true} {
		for _, scope := range []string{"ip", "global"} {
			name := scope + "/json"
			if binary {
				name = scope + "/binary"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				d := &fakeDispatcher{}
				a := NewAcceptor(10, d)
				if scope == "ip" {
					a.rateLimiter = NewRateLimiter(1, time.Hour, 10)
					a.rateLimiter.Allow("")
				} else {
					a.globalBucket = newGlobalRateBucket(0)
				}
				srv, cli := net.Pipe()
				defer srv.Close()
				defer cli.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					if binary {
						a.handleBinaryConn(srv)
					} else {
						a.handleJSONConn(srv, srv)
					}
				}()
				time.Sleep(5100 * time.Millisecond)
				cli.SetDeadline(time.Now().Add(3 * time.Second))
				request := []byte(`{"type":"test"}`)
				if binary {
					writeBinaryFrame(t, cli, wire.MsgJSON, request)
				} else {
					writeJSONFrame(t, cli, request)
				}
				if binary {
					kind, payload, err := wire.ReadFrame(cli)
					if err != nil || kind != wire.MsgError || !strings.Contains(string(payload), "rate limited") {
						t.Fatalf("kind=%v payload=%q err=%v", kind, payload, err)
					}
				} else {
					msg, err := readMessage(cli)
					if err != nil || msg["type"] != "error" || msg["retry_after_ms"] != float64(1000) {
						t.Fatalf("msg=%v err=%v", msg, err)
					}
				}
				d.mu.Lock()
				count := d.jsonMsgs
				d.mu.Unlock()
				if count != 0 {
					t.Fatalf("rejected request dispatched: %d", count)
				}
				// Refill under the production locks (the handler is now waiting to read).
				a.rateLimiter.mu.Lock()
				a.rateLimiter.buckets = make(map[string]*bucket)
				a.rateLimiter.mu.Unlock()
				a.globalBucket.mu.Lock()
				a.globalBucket.tokens = 100
				a.globalBucket.maxFill = 100
				a.globalBucket.rate = 100
				a.globalBucket.mu.Unlock()
				if binary {
					writeBinaryFrame(t, cli, wire.MsgJSON, request)
					kind, _, err := wire.ReadFrame(cli)
					if err != nil || kind == wire.MsgError {
						t.Fatalf("same connection did not recover: %v %v", kind, err)
					}
				} else {
					writeJSONFrame(t, cli, request)
					msg, err := readMessage(cli)
					if err != nil || msg["type"] == "error" {
						t.Fatalf("same connection did not recover: %v %v", msg, err)
					}
				}
				cli.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("handler leaked")
				}
			})
		}
	}
}
