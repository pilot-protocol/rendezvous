// SPDX-License-Identifier: AGPL-3.0-or-later

package accept

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// errDispatcher returns a configurable error from HandleMessage.
type errDispatcher struct {
	fakeDispatcher
	errToReturn error
	rawResp     []byte
}

func (d *errDispatcher) HandleMessage(msg map[string]interface{}, _ string) (map[string]interface{}, error) {
	d.mu.Lock()
	d.jsonMsgs++
	d.mu.Unlock()
	if d.errToReturn != nil {
		return nil, d.errToReturn
	}
	if d.rawResp != nil {
		return map[string]interface{}{rawResponseKey: d.rawResp}, nil
	}
	return map[string]interface{}{"type": "ok"}, nil
}

func runJSONFallbackTest(t *testing.T, d Dispatcher, payload []byte) {
	t.Helper()
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
	writeBinaryFrame(t, cli, wire.MsgJSON, payload)
	time.Sleep(50 * time.Millisecond)
	cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleBinaryConn blocked")
	}
}

// Each test below covers one of the error-keyword branches in the
// errMsg switch inside handleBinaryJSONFallback.
func TestJSONFallback_KnownErrorMessagesPropagate(t *testing.T) {
	t.Parallel()
	cases := []string{
		"rate limited",
		"enterprise feature: required",
		"key expired at 2026-01-01",
		"already a member",
		"node 1 is not a member",
		"cannot demote owner",
		"too many tags",
		"hostname too long",
		"node 9999: not found",
		"invalid foo",
		"requires admin",
		"signature verification failed",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			d := &errDispatcher{errToReturn: errors.New(msg)}
			runJSONFallbackTest(t, d, []byte(`{"type":"x"}`))
		})
	}
}

func TestJSONFallback_GenericErrorBecomesRequestFailed(t *testing.T) {
	t.Parallel()
	d := &errDispatcher{errToReturn: errors.New("an unrelated error")}
	runJSONFallbackTest(t, d, []byte(`{"type":"x"}`))
}

func TestJSONFallback_RawResponseSentinel(t *testing.T) {
	t.Parallel()
	d := &errDispatcher{rawResp: []byte(`{"pre":"baked"}`)}
	runJSONFallbackTest(t, d, []byte(`{"type":"x"}`))
}
