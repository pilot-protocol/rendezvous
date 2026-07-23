// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"testing"

	"github.com/pilot-protocol/rendezvous/routing"
)

func TestHandlePunch_StrictOff_UntrustedPairStillResolved(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
		},
	}
	st := routing.NewStore(be)

	resp, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err != nil {
		t.Fatalf("flag-off behavior must not require trust: %v", err)
	}
	if resp["node_b_addr"] != "2.2.2.2:4000" {
		t.Fatalf("resp=%v", resp)
	}
}

func TestHandlePunch_StrictOn_UntrustedPairDenied(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		strict: true,
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
		},
	}
	st := routing.NewStore(be)

	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err == nil {
		t.Fatal("expected strict mode to deny a punch between untrusted nodes")
	}
}

func TestHandlePunch_StrictOn_TrustedPairAllowed(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		strict: true,
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
			2: {"pk2", "2.2.2.2:4000"},
		},
		trusted: map[[2]uint32]bool{{1, 2}: true},
	}
	st := routing.NewStore(be)

	resp, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err != nil {
		t.Fatalf("expected a trusted pair to be allowed, got: %v", err)
	}
	if resp["node_a_addr"] != "1.1.1.1:4000" || resp["node_b_addr"] != "2.2.2.2:4000" {
		t.Fatalf("resp=%v", resp)
	}
}
