// SPDX-License-Identifier: AGPL-3.0-or-later

package trust_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/pilot-protocol/rendezvous/trust"
)

// keyedNodes is a NodeView whose nodes have real Ed25519 keys, so reports
// go through the signature path, not the admin token.
type keyedNodes struct {
	fakeNodes
	priv map[uint32]ed25519.PrivateKey
}

func newKeyedNodes(t *testing.T, ids ...uint32) *keyedNodes {
	t.Helper()
	k := &keyedNodes{fakeNodes: fakeNodes{nodes: map[uint32]fakeNode{}, adminToken: "secret"}, priv: map[uint32]ed25519.PrivateKey{}}
	for _, id := range ids {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		k.nodes[id] = fakeNode{pubKey: pub}
		k.priv[id] = priv
	}
	return k
}

// signed is a report_trust or revoke_trust request from a to b, signed by a.
func (k *keyedNodes) signed(op string, a, b uint32) map[string]interface{} {
	sig := ed25519.Sign(k.priv[a], []byte(fmt.Sprintf("%s:%d:%d", op, a, b)))
	return map[string]interface{}{"node_id": float64(a), "peer_id": float64(b), "signature": base64.StdEncoding.EncodeToString(sig)}
}

func checkTrust(t *testing.T, st *trust.Store, a, b uint32) bool {
	t.Helper()
	resp, err := st.HandleCheckTrust(map[string]interface{}{"node_id": float64(a), "peer_id": float64(b)})
	if err != nil {
		t.Fatalf("check_trust: %v", err)
	}
	return resp["trusted"] == true
}

// The security report of 2026-11-08: node 2 alone signs report_trust:2:1.
// That must not make 1 and 2 trust each other, neither for IsTrusted (the
// registry's lookup gate) nor for check_trust (a private daemon's gate).
func TestReportTrustNeedsBothNodes(t *testing.T) {
	t.Parallel()
	nodes := newKeyedNodes(t, 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	resp, err := st.HandleReportTrust(nodes.signed("report_trust", 2, 1))
	if err != nil {
		t.Fatalf("one-sided report: %v", err)
	}
	if resp["type"] != "report_trust_ok" || resp["trusted"] != false {
		t.Fatalf("one-sided report answered %v, want report_trust_ok with trusted false", resp)
	}
	if st.IsTrusted(1, 2) || st.IsTrusted(2, 1) || checkTrust(t, st, 1, 2) || checkTrust(t, st, 2, 1) || st.Count() != 0 {
		t.Fatal("a report signed by one node made the pair")
	}
	// Reporting again, any number of times, changes nothing.
	for range 3 {
		if _, err := st.HandleReportTrust(nodes.signed("report_trust", 2, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if st.IsTrusted(1, 2) {
		t.Fatal("repeated one-sided reports made the pair")
	}

	// Node 1 reports node 2 too: now it is mutual.
	resp, err = st.HandleReportTrust(nodes.signed("report_trust", 1, 2))
	if err != nil || resp["trusted"] != true {
		t.Fatalf("second side: %v %v", resp, err)
	}
	if !st.IsTrusted(1, 2) || !checkTrust(t, st, 2, 1) || st.Count() != 1 {
		t.Fatal("both nodes reported, no pair")
	}
	// The re-sync on re-registration: reported again, still trusted.
	if resp, err := st.HandleReportTrust(nodes.signed("report_trust", 2, 1)); err != nil || resp["trusted"] != true {
		t.Fatalf("re-sync: %v %v", resp, err)
	}
}

// A report signed with someone else's key, or claiming another node's
// identity, is refused as before.
func TestReportTrustForgedSignature(t *testing.T) {
	t.Parallel()
	nodes := newKeyedNodes(t, 1, 2, 3)
	st := trust.NewStore(nodes, noopCallbacks())
	req := nodes.signed("report_trust", 3, 2) // node 3's signature...
	req["node_id"] = float64(1)               // ...on a report as node 1
	if _, err := st.HandleReportTrust(req); err == nil {
		t.Fatal("forged report accepted")
	}
	if _, err := st.HandleReportTrust(nodes.signed("report_trust", 2, 1)); err != nil {
		t.Fatal(err)
	}
	if st.IsTrusted(1, 2) {
		t.Fatal("a forged report counted as node 1's consent")
	}
}

// Revoking withdraws a report still waiting, so a later report from the
// other node alone does not complete the pair; either node revokes a pair.
func TestRevokeWithdrawsAWaitingReport(t *testing.T) {
	t.Parallel()
	nodes := newKeyedNodes(t, 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())

	if _, err := st.HandleReportTrust(nodes.signed("report_trust", 1, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.HandleRevokeTrust(nodes.signed("revoke_trust", 1, 2)); err != nil {
		t.Fatalf("withdrawing a waiting report: %v", err)
	}
	if _, err := st.HandleReportTrust(nodes.signed("report_trust", 2, 1)); err != nil {
		t.Fatal(err)
	}
	if st.IsTrusted(1, 2) {
		t.Fatal("node 1 withdrew its report, yet node 2's alone made the pair")
	}
	// Node 1 reports again: mutual. Then node 2 alone revokes the pair.
	if _, err := st.HandleReportTrust(nodes.signed("report_trust", 1, 2)); err != nil {
		t.Fatal(err)
	}
	if !st.IsTrusted(1, 2) {
		t.Fatal("no pair after both reported")
	}
	if _, err := st.HandleRevokeTrust(nodes.signed("revoke_trust", 2, 1)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if st.IsTrusted(1, 2) {
		t.Fatal("revoked pair still trusted")
	}
	// Nothing left to revoke: the old error.
	if _, err := st.HandleRevokeTrust(nodes.signed("revoke_trust", 2, 1)); err == nil {
		t.Fatal("revoking nothing succeeded")
	}
}

// Both nodes reporting at the same moment make exactly one pair.
func TestReportTrustBothAtOnce(t *testing.T) {
	t.Parallel()
	const pairs = 200
	ids := make([]uint32, 0, 2*pairs)
	for i := range uint32(2 * pairs) {
		ids = append(ids, i+1)
	}
	nodes := newKeyedNodes(t, ids...)
	st := trust.NewStore(nodes, noopCallbacks())
	reqs := make([]map[string]interface{}, 0, 2*pairs)
	for i := uint32(0); i < pairs; i++ {
		a, b := 2*i+1, 2*i+2
		reqs = append(reqs, nodes.signed("report_trust", a, b), nodes.signed("report_trust", b, a))
	}
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.HandleReportTrust(r); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if st.Count() != pairs {
		t.Fatalf("%d pairs, want %d", st.Count(), pairs)
	}
}

// A node can't report trust in itself.
func TestReportTrustInItself(t *testing.T) {
	t.Parallel()
	nodes := newKeyedNodes(t, 1)
	st := trust.NewStore(nodes, noopCallbacks())
	if _, err := st.HandleReportTrust(nodes.signed("report_trust", 1, 1)); err == nil || st.Count() != 0 {
		t.Fatalf("self report: %v, %d pairs", err, st.Count())
	}
}

// The signed handshake relay still makes the pair in one step: the request
// is the requester's consent and the signed accept the responder's.
func TestHandshakeRelayStillMakesThePair(t *testing.T) {
	t.Parallel()
	nodes := newKeyedNodes(t, 1, 2)
	st := trust.NewStore(nodes, noopCallbacks())
	reqSig := ed25519.Sign(nodes.priv[2], []byte("handshake:2:1"))
	if _, err := st.HandleRequestHandshake(map[string]interface{}{
		"from_node_id": float64(2), "to_node_id": float64(1), "justification": "hi",
		"signature": base64.StdEncoding.EncodeToString(reqSig),
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	respSig := ed25519.Sign(nodes.priv[1], []byte("respond:1:2"))
	if _, err := st.HandleRespondHandshake(map[string]interface{}{
		"node_id": float64(1), "peer_id": float64(2), "accept": true,
		"signature": base64.StdEncoding.EncodeToString(respSig),
	}); err != nil {
		t.Fatalf("respond: %v", err)
	}
	if !st.IsTrusted(1, 2) {
		t.Fatal("an accepted relayed handshake made no pair")
	}
}

// A node without a key can't sign, so nobody may request or accept a
// handshake in its name without the admin token. Both used to skip
// verification for such a node (audit, 2026-11-08), so anyone could mint a
// trust pair with it.
func TestKeylessNodeHandshakeNeedsAdminToken(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2) // no keys
	st := trust.NewStore(nodes, noopCallbacks())

	if _, err := st.HandleRequestHandshake(map[string]interface{}{"from_node_id": float64(2), "to_node_id": float64(1), "justification": "hi"}); err == nil {
		t.Fatal("unsigned request in a keyless node's name accepted")
	}
	if _, err := st.HandleRequestHandshake(map[string]interface{}{"from_node_id": float64(2), "to_node_id": float64(1), "justification": "hi", "admin_token": "secret"}); err != nil {
		t.Fatalf("operator's request: %v", err)
	}
	if _, err := st.HandleRespondHandshake(map[string]interface{}{"node_id": float64(1), "peer_id": float64(2), "accept": true}); err == nil {
		t.Fatal("unsigned accept in a keyless node's name accepted")
	}
	if st.IsTrusted(1, 2) {
		t.Fatal("an unsigned accept made a trust pair")
	}
	if _, err := st.HandleRespondHandshake(map[string]interface{}{"node_id": float64(1), "peer_id": float64(2), "accept": true, "admin_token": "secret"}); err != nil {
		t.Fatalf("operator's accept: %v", err)
	}
	if !st.IsTrusted(1, 2) {
		t.Fatal("the operator's accept made no pair")
	}
}
