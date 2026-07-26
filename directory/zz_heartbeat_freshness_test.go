// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/registry/wire"
)

// heartbeatProbe wires a test Store so the challenge string handed to
// signature verification is observable, the clock is controllable, and
// the freshness gate can be toggled.
type heartbeatProbe struct {
	st *Store

	mu         sync.Mutex
	challenges []string
	now        time.Time
	strict     bool
	verifyErr  error
}

func newHeartbeatProbe(t *testing.T, nodeID uint32) *heartbeatProbe {
	t.Helper()
	p := &heartbeatProbe{now: time.Unix(1_800_000_000, 0)}
	p.st = newTestStore(t)

	p.st.cb.Now = func() time.Time {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.now
	}
	p.st.cb.VerifyNodeSignature = func(_ []byte, _ string, _ map[string]interface{}, challenge string) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.challenges = append(p.challenges, challenge)
		return p.verifyErr
	}
	p.st.cb.StrictHeartbeatFreshness = func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.strict
	}

	p.st.mu.Lock()
	p.st.nodes[nodeID] = &NodeInfo{ID: nodeID, PublicKey: []byte("pubkey")}
	p.st.mu.Unlock()
	return p
}

func (p *heartbeatProbe) setStrict(v bool) {
	p.mu.Lock()
	p.strict = v
	p.mu.Unlock()
}

func (p *heartbeatProbe) advance(d time.Duration) {
	p.mu.Lock()
	p.now = p.now.Add(d)
	p.mu.Unlock()
}

func (p *heartbeatProbe) unixNow() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.now.Unix()
}

func (p *heartbeatProbe) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.challenges...)
}

func (p *heartbeatProbe) reset() {
	p.mu.Lock()
	p.challenges = nil
	p.mu.Unlock()
}

// TestHeartbeatChallengeDefaultsUnbound pins the wire-compatible default:
// with the gate off the challenge covers only the node id, no ts field is
// required, and the verification cache still applies.
func TestHeartbeatChallengeDefaultsUnbound(t *testing.T) {
	t.Parallel()
	const nodeID = 4321
	p := newHeartbeatProbe(t, nodeID)

	if _, err := p.st.HandleHeartbeat(map[string]interface{}{"node_id": float64(nodeID)}); err != nil {
		t.Fatalf("heartbeat without ts rejected while the gate is off: %v", err)
	}
	got := p.seen()
	if len(got) != 1 || got[0] != fmt.Sprintf("heartbeat:%d", nodeID) {
		t.Fatalf("challenge = %v; want [heartbeat:%d]", got, nodeID)
	}

	// Second heartbeat inside the cache window: verification is reused.
	p.reset()
	if _, err := p.st.HandleHeartbeat(map[string]interface{}{"node_id": float64(nodeID)}); err != nil {
		t.Fatalf("second heartbeat: %v", err)
	}
	if n := len(p.seen()); n != 0 {
		t.Errorf("verification ran %d times inside the cache window; want 0 (cache reused)", n)
	}
}

// TestHeartbeatFreshnessBindsTimestamp pins the gated behaviour: the
// timestamp the caller supplies is bound into the challenge, so a
// signature is only good for the moment it was produced for.
func TestHeartbeatFreshnessBindsTimestamp(t *testing.T) {
	t.Parallel()
	const nodeID = 4322
	p := newHeartbeatProbe(t, nodeID)
	p.setStrict(true)

	ts := p.unixNow()
	if _, err := p.st.HandleHeartbeat(map[string]interface{}{
		"node_id": float64(nodeID),
		"ts":      float64(ts),
	}); err != nil {
		t.Fatalf("fresh heartbeat rejected: %v", err)
	}
	got := p.seen()
	want := fmt.Sprintf("heartbeat:%d:%d", nodeID, ts)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("challenge = %v; want [%s]", got, want)
	}
}

// TestHeartbeatFreshnessRejectsReplay is the property the gate exists
// for: a heartbeat captured off the wire stops being accepted once its
// timestamp falls outside the skew window, so it can no longer hold a
// node that is gone in the "seen recently" state.
func TestHeartbeatFreshnessRejectsReplay(t *testing.T) {
	t.Parallel()
	const nodeID = 4323
	p := newHeartbeatProbe(t, nodeID)
	p.setStrict(true)

	captured := map[string]interface{}{
		"node_id": float64(nodeID),
		"ts":      float64(p.unixNow()),
	}
	if _, err := p.st.HandleHeartbeat(captured); err != nil {
		t.Fatalf("original heartbeat rejected: %v", err)
	}

	// Replayed well after the fact.
	p.advance(heartbeatMaxSkew + time.Minute)
	if _, err := p.st.HandleHeartbeat(captured); err == nil {
		t.Fatal("replayed heartbeat accepted after the skew window; it should be refused")
	}

	// A heartbeat minted now still works, so the gate rejects on age and
	// not by refusing everything.
	if _, err := p.st.HandleHeartbeat(map[string]interface{}{
		"node_id": float64(nodeID),
		"ts":      float64(p.unixNow()),
	}); err != nil {
		t.Fatalf("current heartbeat rejected: %v", err)
	}
}

// TestHeartbeatFreshnessRequiresTimestamp covers the missing-field and
// future-timestamp cases.
func TestHeartbeatFreshnessRequiresTimestamp(t *testing.T) {
	t.Parallel()
	const nodeID = 4324
	p := newHeartbeatProbe(t, nodeID)
	p.setStrict(true)

	if _, err := p.st.HandleHeartbeat(map[string]interface{}{"node_id": float64(nodeID)}); err == nil {
		t.Error("heartbeat with no ts accepted while freshness is enforced")
	}
	if _, err := p.st.HandleHeartbeat(map[string]interface{}{
		"node_id": float64(nodeID),
		"ts":      float64(p.unixNow() + int64((heartbeatMaxSkew+time.Minute)/time.Second)),
	}); err == nil {
		t.Error("heartbeat timestamped in the future accepted; the skew window is two-sided")
	}
}

// TestHeartbeatFreshnessBypassesVerifyCache pins that the gate is not
// undone by the signature-verification cache: without this, one accepted
// heartbeat would wave through anything sent in the following two
// minutes, signature and timestamp unchecked.
func TestHeartbeatFreshnessBypassesVerifyCache(t *testing.T) {
	t.Parallel()
	const nodeID = 4325
	p := newHeartbeatProbe(t, nodeID)
	p.setStrict(true)

	beat := func() error {
		_, err := p.st.HandleHeartbeat(map[string]interface{}{
			"node_id": float64(nodeID),
			"ts":      float64(p.unixNow()),
		})
		return err
	}
	if err := beat(); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	p.reset()

	// Well inside the cache window.
	p.advance(time.Second)
	p.mu.Lock()
	p.verifyErr = errors.New("bad signature")
	p.mu.Unlock()

	if err := beat(); err == nil {
		t.Fatal("heartbeat with an invalid signature accepted inside the cache window")
	}
	if n := len(p.seen()); n != 1 {
		t.Errorf("verification ran %d times; want 1 (the cache must not be consulted)", n)
	}
}

// TestBinaryHeartbeatRefusedWhenFreshnessEnforced pins that the gate
// cannot be sidestepped by switching encodings. The binary heartbeat
// payload is a fixed node id + signature with no field for a timestamp,
// so while freshness is enforced it is refused rather than silently
// accepted on the original unbound challenge.
func TestBinaryHeartbeatRefusedWhenFreshnessEnforced(t *testing.T) {
	t.Parallel()
	const nodeID = 4326
	p := newHeartbeatProbe(t, nodeID)

	// A genuinely valid binary heartbeat: real key, real signature over
	// the unbound challenge. It is accepted on this encoding today, which
	// is exactly why leaving the encoding open would make the gate
	// decorative.
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p.st.mu.Lock()
	p.st.nodes[nodeID].PublicKey = id.PublicKey
	p.st.mu.Unlock()
	payload := wire.EncodeHeartbeatReq(nodeID, id.Sign([]byte(fmt.Sprintf("heartbeat:%d", nodeID))))

	send := func() (byte, error) {
		srv, cli := net.Pipe()
		defer srv.Close()
		defer cli.Close()

		replies := make(chan wireReply, 1)
		go func() {
			typ, body, err := wire.ReadFrame(cli)
			replies <- wireReply{typ: typ, payload: body, err: err}
		}()

		done := make(chan struct{})
		go func() {
			p.st.HandleBinaryHeartbeat(srv, payload)
			close(done)
		}()

		var got wireReply
		select {
		case got = <-replies:
		case <-time.After(2 * time.Second):
			t.Fatal("no reply to the binary heartbeat")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("HandleBinaryHeartbeat blocked")
		}
		return got.typ, got.err
	}

	// Baseline: the request is well-formed and accepted with the gate off.
	if typ, err := send(); err != nil {
		t.Fatalf("read reply: %v", err)
	} else if typ != wire.MsgHeartbeatOK {
		t.Fatalf("setup: binary heartbeat answered with frame type %#x; want MsgHeartbeatOK — the request must be valid for this test to mean anything", typ)
	}

	p.st.mu.RLock()
	p.st.nodes[nodeID].LastSeenNano.Store(0)
	p.st.mu.RUnlock()

	// Same request, gate on: refused, because this encoding cannot carry
	// the timestamp the challenge would bind.
	p.setStrict(true)
	if typ, err := send(); err != nil {
		t.Fatalf("read reply: %v", err)
	} else if typ != wire.MsgError {
		t.Fatalf("binary heartbeat answered with frame type %#x while freshness is enforced; want an error frame", typ)
	}

	p.st.mu.RLock()
	node := p.st.nodes[nodeID]
	p.st.mu.RUnlock()
	if node.LastSeenNano.Load() != 0 {
		t.Error("a refused binary heartbeat still refreshed the node's last-seen time")
	}
}

type wireReply struct {
	typ     byte
	payload []byte
	err     error
}
