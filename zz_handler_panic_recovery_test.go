// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// Regression for P0 DoS vector: a panicking handler in the dispatch
// table crashes the entire registry process. The current handleMessage
// invokes the handler via `return h(s, msg, remoteAddr)` with no
// recover wrapper — a single bad request from a peer can take down the
// whole registry serving the fleet.
//
// Fix: wrap the dispatch call in defer recover() and convert panics to
// errors so the offending caller gets an error response and the
// process keeps serving everyone else.

import (
	"strings"
	"testing"
)

// TestHandleMessageRecoversFromHandlerPanic registers a handler that
// panics, then calls handleMessage and asserts the panic was contained
// (function returned an error instead of crashing the process).
func TestHandleMessageRecoversFromHandlerPanic(t *testing.T) {
	// NOT parallel — mutates the package-global handlers map.
	const msgType = "__panic_test_msgtype__"

	prior, hadPrior := handlers[msgType]
	handlers[msgType] = func(s *Server, msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
		panic("boom — simulated panic in a registry handler")
	}
	t.Cleanup(func() {
		if hadPrior {
			handlers[msgType] = prior
		} else {
			delete(handlers, msgType)
		}
	})

	s := newTestServer(t, "")

	// Without the recover wrapper, this CRASHES the test process.
	// With the wrapper, it returns an error.
	resp, err := s.handleMessage(map[string]interface{}{"type": msgType}, "127.0.0.1:9999")

	if err == nil {
		t.Fatalf("handleMessage returned no error for panicking handler — recover wrapper missing or broken (resp=%v)", resp)
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("expected error to mention 'panic'; got %q", err.Error())
	}
}
