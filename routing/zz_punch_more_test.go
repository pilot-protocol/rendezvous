// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"testing"

	"github.com/pilot-protocol/rendezvous/routing"
)

func TestHandlePunch_NoBackendWiredErrors(t *testing.T) {
	t.Parallel()
	st := routing.NewStore(nil)
	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err == nil {
		t.Error("expected error when backend is nil")
	}
}

func TestHandlePunch_RequesterNotFound(t *testing.T) {
	t.Parallel()
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			2: {"pk2", "2.2.2.2:4000"},
		},
	}
	st := routing.NewStore(be)
	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1), // not in backend
		"node_a":       float64(1),
		"node_b":       float64(2),
	})
	if err == nil {
		t.Error("expected requester-not-found error")
	}
}

func TestHandlePunch_NodeBNotFound(t *testing.T) {
	t.Parallel()
	// requester=1 found, node_b=99 absent.
	be := &stubBackend{
		nodes: map[uint32]struct {
			pubKey string
			addr   string
		}{
			1: {"pk1", "1.1.1.1:4000"},
		},
	}
	st := routing.NewStore(be)
	_, err := st.HandlePunch(map[string]interface{}{
		"requester_id": float64(1),
		"node_a":       float64(1),
		"node_b":       float64(99),
	})
	if err == nil {
		t.Error("expected node-b-not-found error")
	}
}
