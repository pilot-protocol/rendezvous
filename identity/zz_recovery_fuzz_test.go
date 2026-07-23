// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
)

// fuzzStore builds a recovery Store whose credential verifiers always REJECT.
// The point of the fuzz is the wire/decode + argument-extraction path of the
// three security handlers (submit_badge / enroll_recovery / recover_identity):
// no input — however malformed — may panic, and every input must fail closed
// (return an error, never mutate the binding). With the verifiers stubbed to
// reject, a successful return on garbage would be a fail-OPEN regression, which
// the body asserts can never happen.
func fuzzStore() (*Store, *fakeNodeView) {
	const nodeID uint32 = 0x1ABCD
	fv := &fakeNodeView{nodes: map[uint32]fakeNode{nodeID: {pubKey: []byte("the-original-pinned-key-32bytes!")}}}
	fv.nodes[nodeID] = fakeNode{
		pubKey:    []byte("the-original-pinned-key-32bytes!"),
		badge:     "ORIGINAL-BADGE",
		provider:  "github",
		recCommit: "ENROLLED-COMMITMENT==",
	}
	st := NewStore(fv, Callbacks{
		Save:         func() {},
		Audit:        func(string, ...any) {},
		OnKeyRotated: func(uint32, string, string) {},
		RecordWAL:    func(uint32, string, string, bool) {},
	})
	reject := func() error { return errRejected }
	st.verifyBadge = func(string, string, uint32) (badgeverify.Badge, error) {
		return badgeverify.Badge{}, reject()
	}
	st.verifyEnrollment = func(string, string) (badgeverify.Enrollment, error) {
		return badgeverify.Enrollment{}, reject()
	}
	st.verifyRecovery = func(string, string) (badgeverify.Recovery, error) {
		return badgeverify.Recovery{}, reject()
	}
	return st, fv
}

type rejectedErr struct{}

func (rejectedErr) Error() string { return "stub: credential rejected" }

var errRejected = rejectedErr{}

// FuzzRecoveryWireDecode feeds arbitrary bytes as the JSON request body for each
// of the three security commands. It asserts:
//   - no handler panics on any input (the deferred recover catches it), and
//   - with the credential verifiers stubbed to reject, no handler ever returns
//     a success (nil error) — i.e. garbage can never force a fail-open badge
//     submission, recovery enrollment, or identity rebind, and the node's
//     pinned key/badge are never mutated.
func FuzzRecoveryWireDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"node_id":109517}`,
		`{"node_id":"not-a-number"}`,
		`{"node_id":109517,"badge":"b","badge_sig":"s","signature":"AAAA"}`,
		`{"node_id":109517,"enrollment":"e","enrollment_sig":"s","signature":"AAAA"}`,
		`{"node_id":109517,"recovery":"r","recovery_sig":"s","new_public_key":"AAAA"}`,
		`{"node_id":1.5e308,"badge":null,"signature":[]}`,
		`{"node_id":-1}`,
		`{"node_id":4294967296}`,
		"{\"badge\":\"\u0000\uffff\",\"signature\":\"!!!notbase64!!!\"}",
		`[1,2,3]`,
		`"a string"`,
		`null`,
		`{"recovery":"r","recovery_sig":"s","new_public_key":"` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" + `"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		var msg map[string]interface{}
		// Mirror the real wire path (server_util.readMessage): JSON-decode the
		// length-prefixed body into a map. A decode failure is the registry
		// rejecting the frame before dispatch — nothing to fuzz past that.
		if err := json.Unmarshal(body, &msg); err != nil || msg == nil {
			return
		}

		st, fv := fuzzStore()
		origKey := string(fv.nodes[0x1ABCD].pubKey)
		origBadge := fv.nodes[0x1ABCD].badge

		// Each call must either return an error or not panic. Because the
		// verifiers reject, a nil error here would be a fail-open bug.
		mustFailClosed := func(name string, resp map[string]interface{}, err error) {
			t.Helper()
			if err == nil {
				t.Fatalf("%s returned success on fuzzed/garbage input (fail-open): resp=%v body=%q", name, resp, body)
			}
		}

		r1, e1 := st.HandleSubmitBadge(clone(msg))
		mustFailClosed("HandleSubmitBadge", r1, e1)

		r2, e2 := st.HandleEnrollRecovery(clone(msg))
		mustFailClosed("HandleEnrollRecovery", r2, e2)

		r3, e3 := st.HandleRecoverIdentity(clone(msg))
		mustFailClosed("HandleRecoverIdentity", r3, e3)

		// The binding and badge must be byte-for-byte unchanged after any
		// rejected garbage request.
		if got := string(fv.nodes[0x1ABCD].pubKey); got != origKey {
			t.Fatalf("pinned key mutated by a rejected request: body=%q", body)
		}
		if got := fv.nodes[0x1ABCD].badge; got != origBadge {
			t.Fatalf("badge mutated by a rejected request: body=%q", body)
		}
	})
}

// clone deep-enough copies a decoded message so a handler that mutates its
// argument map can't leak state into the next handler call within one fuzz
// iteration.
func clone(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// recoveryWindow is asserted by the deterministic test below; kept here so the
// fuzz and the window test share the same constant expectation.
const fuzzMaxRecoveryWindow = 30 * time.Minute
