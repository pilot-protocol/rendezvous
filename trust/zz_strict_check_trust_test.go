// SPDX-License-Identifier: AGPL-3.0-or-later

package trust_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/rendezvous/trust"
)

func strictCallbacks(strict bool) trust.Callbacks {
	cb := noopCallbacks()
	cb.StrictDirectoryAuth = func() bool { return strict }
	return cb
}

func TestHandleCheckTrust_StrictOff_AnyCallerCanQuery(t *testing.T) {
	t.Parallel()
	nodes := newFakeNodes("secret", 1, 2)
	st := trust.NewStore(nodes, strictCallbacks(false))

	resp, err := st.HandleCheckTrust(map[string]interface{}{
		"node_id": float64(1),
		"peer_id": float64(2),
	})
	if err != nil {
		t.Fatalf("flag-off behavior must not require a requester: %v", err)
	}
	if resp["trusted"] != false {
		t.Fatalf("resp=%v", resp)
	}
}

func TestHandleCheckTrust_StrictOn_RequiresParticipant(t *testing.T) {
	t.Parallel()
	id1, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodes := &fakeNodes{nodes: map[uint32]fakeNode{
		1: {pubKey: id1.PublicKey},
		2: {},
		3: {},
	}}
	st := trust.NewStore(nodes, strictCallbacks(true))

	sig := id1.Sign([]byte(fmt.Sprintf("check_trust:%d:%d", 1, 2)))
	_, err = st.HandleCheckTrust(map[string]interface{}{
		"node_id":      float64(1),
		"peer_id":      float64(2),
		"requester_id": float64(3),
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	if err == nil {
		t.Fatal("expected strict mode to deny a requester that is not a participant in the pair")
	}
}

func TestHandleCheckTrust_StrictOn_ParticipantWithValidSignatureAllowed(t *testing.T) {
	t.Parallel()
	id1, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodes := &fakeNodes{nodes: map[uint32]fakeNode{
		1: {pubKey: id1.PublicKey},
		2: {},
	}}
	st := trust.NewStore(nodes, strictCallbacks(true))

	sig := id1.Sign([]byte(fmt.Sprintf("check_trust:%d:%d", 1, 2)))
	resp, err := st.HandleCheckTrust(map[string]interface{}{
		"node_id":      float64(1),
		"peer_id":      float64(2),
		"requester_id": float64(1),
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("expected a valid participant signature to be allowed, got: %v", err)
	}
	if resp["trusted"] != false {
		t.Fatalf("resp=%v", resp)
	}
}

func TestHandleCheckTrust_StrictOn_InvalidSignatureDenied(t *testing.T) {
	t.Parallel()
	id1, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nodes := &fakeNodes{nodes: map[uint32]fakeNode{
		1: {pubKey: id1.PublicKey},
		2: {},
	}}
	st := trust.NewStore(nodes, strictCallbacks(true))

	_, err = st.HandleCheckTrust(map[string]interface{}{
		"node_id":      float64(1),
		"peer_id":      float64(2),
		"requester_id": float64(1),
		"signature":    base64.StdEncoding.EncodeToString(make([]byte, 64)),
	})
	if err == nil {
		t.Fatal("expected an invalid signature to be denied under strict mode")
	}
}
