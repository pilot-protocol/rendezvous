// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/registry/wire"
)

// TestHandleBinaryLookup_DoesNotLeakExternalID is the privacy regression guard
// for the BINARY lookup path. The JSON HandleLookup path is covered by
// TestHandleLookupRedactsExternalIDSurfacesBadge; this asserts the same
// invariant on the binary wire path, which encodes its own LookupResp frame
// (and could regress independently if a refactor passed node.ExternalID into
// the last EncodeLookupResp argument). The decoded response must carry an
// EMPTY external_id even though the node holds a raw external identity.
func TestHandleBinaryLookup_DoesNotLeakExternalID(t *testing.T) {
	t.Parallel()
	st := newTestStore(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const nodeID uint32 = 0x2BEEF
	st.mu.Lock()
	st.nodes[nodeID] = &NodeInfo{
		ID:         nodeID,
		PublicKey:  id.PublicKey,
		Public:     true,
		RealAddr:   "9.9.9.9:4000",
		ExternalID: "github|secret-handle", // must NEVER be surfaced
		Badge:      "pilotbadge:v1:1:github:1700000000:0:bdg-v1:",
		BadgeSig:   "sig",
	}
	st.mu.Unlock()

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	// Read the response frame on the client side concurrently with the handler
	// writing it.
	type result struct {
		res wire.LookupResult
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
		msgType, payload, err := wire.ReadFrame(cli)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		if msgType != wire.MsgLookupOK {
			resCh <- result{err: errUnexpectedFrame(msgType)}
			return
		}
		r, derr := wire.DecodeLookupResp(payload)
		resCh <- result{res: r, err: derr}
	}()

	st.HandleBinaryLookup(srv, wire.EncodeLookupReq(nodeID))

	select {
	case got := <-resCh:
		if got.err != nil {
			t.Fatalf("read/decode lookup response: %v", got.err)
		}
		if got.res.ExternalID != "" {
			t.Fatalf("binary lookup leaked external_id: %q", got.res.ExternalID)
		}
		if got.res.NodeID != nodeID {
			t.Fatalf("wrong node in response: got %d want %d", got.res.NodeID, nodeID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for binary lookup response")
	}
}

type unexpectedFrame byte

func (u unexpectedFrame) Error() string { return "unexpected frame type" }

func errUnexpectedFrame(b byte) error { return unexpectedFrame(b) }
