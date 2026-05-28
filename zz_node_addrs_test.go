// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
)

func TestServer_NodeAddrs_Empty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	addrA, okA, addrB, okB := s.NodeAddrs(1, 2)
	if okA || okB {
		t.Errorf("empty server: got (%v, %v), want (false, false)", okA, okB)
	}
	if addrA != "" || addrB != "" {
		t.Errorf("addrs = (%q, %q), want empty", addrA, addrB)
	}
}

func TestServer_NodeAddrs_BothFound(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[1] = &NodeInfo{ID: 1, RealAddr: "1.1.1.1:4000"}
	s.nodes[2] = &NodeInfo{ID: 2, RealAddr: "2.2.2.2:4000"}
	s.mu.Unlock()

	addrA, okA, addrB, okB := s.NodeAddrs(1, 2)
	if !okA || addrA != "1.1.1.1:4000" {
		t.Errorf("nodeA: got (%q, %v)", addrA, okA)
	}
	if !okB || addrB != "2.2.2.2:4000" {
		t.Errorf("nodeB: got (%q, %v)", addrB, okB)
	}
}

func TestServer_NodeAddrs_OneMissing(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	s.nodes[1] = &NodeInfo{ID: 1, RealAddr: "1.1.1.1:4000"}
	s.mu.Unlock()

	addrA, okA, _, okB := s.NodeAddrs(1, 9999)
	if !okA || addrA != "1.1.1.1:4000" {
		t.Errorf("nodeA: got (%q, %v)", addrA, okA)
	}
	if okB {
		t.Error("nodeB should be missing")
	}
}

func TestServer_VerifyPunchSignature_NilPubKeyAdminTokenFallback(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// pubKey nil + valid admin_token → success via admin fallback.
	err := s.VerifyPunchSignature(nil, "ADM", map[string]interface{}{"admin_token": "ADM"}, "punch:1:2")
	if err != nil {
		t.Errorf("admin fallback: %v", err)
	}
	// pubKey nil + wrong token → error.
	err = s.VerifyPunchSignature(nil, "ADM", map[string]interface{}{"admin_token": "wrong"}, "punch:1:2")
	if err == nil {
		t.Error("wrong token: want error")
	}
}
