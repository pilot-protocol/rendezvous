// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"sync"
	"time"
)

// handshakeShards is the shard count for handshake relay state. A power of
// two so the index is a mask. Every agent polls its handshake inbox on a
// timer, so at fleet scale a single global mutex serialised every poll even
// though each one touches only its own node id — that lock dominated the
// registry's blocking profile. Sharding by node id lets polls for different
// nodes proceed in parallel.
const handshakeShards = 256

func handshakeShardIdx(nodeID uint32) uint32 {
	return (nodeID * 2654435761) & (handshakeShards - 1)
}

var (
	// errInboxFull reports that a node's handshake inbox is at capacity.
	errInboxFull = errors.New("handshake inbox full")
	// errAlreadyPending reports a duplicate request from the same origin.
	errAlreadyPending = errors.New("handshake request already pending")
)

// handshakeState is the sharded store for handshake relay inboxes,
// responses and pending-request tracking. Every mutating operation touches
// exactly one node id, so no code path needs two shards at once and there
// is no lock ordering to observe.
type handshakeState struct {
	shards [handshakeShards]struct {
		mu        sync.Mutex
		inbox     map[uint32][]*HandshakeRelayMsg
		responses map[uint32][]*HandshakeResponseMsg
		pending   map[uint32]map[uint32]struct{}
	}
}

func newHandshakeState() *handshakeState {
	hs := &handshakeState{}
	for i := range hs.shards {
		hs.shards[i].inbox = make(map[uint32][]*HandshakeRelayMsg)
		hs.shards[i].responses = make(map[uint32][]*HandshakeResponseMsg)
		hs.shards[i].pending = make(map[uint32]map[uint32]struct{})
	}
	return hs
}

// relay appends a handshake request to toNodeID's inbox and records it as
// pending. Returns errInboxFull or errAlreadyPending when rejected.
func (hs *handshakeState) relay(toNodeID, fromNodeID uint32, justification string, maxInbox int) error {
	sh := &hs.shards[handshakeShardIdx(toNodeID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if len(sh.inbox[toNodeID]) >= maxInbox {
		return errInboxFull
	}
	for _, existing := range sh.inbox[toNodeID] {
		if existing.FromNodeID == fromNodeID {
			return errAlreadyPending
		}
	}
	sh.inbox[toNodeID] = append(sh.inbox[toNodeID], &HandshakeRelayMsg{
		FromNodeID:    fromNodeID,
		Justification: justification,
		Timestamp:     time.Now(),
	})
	if sh.pending[toNodeID] == nil {
		sh.pending[toNodeID] = make(map[uint32]struct{})
	}
	sh.pending[toNodeID][fromNodeID] = struct{}{}
	return nil
}

// pop returns and clears nodeID's request and response inboxes.
func (hs *handshakeState) pop(nodeID uint32) ([]*HandshakeRelayMsg, []*HandshakeResponseMsg) {
	sh := &hs.shards[handshakeShardIdx(nodeID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	inbox := sh.inbox[nodeID]
	delete(sh.inbox, nodeID)
	resp := sh.responses[nodeID]
	delete(sh.responses, nodeID)
	return inbox, resp
}

// takePending consumes a pending request from peerID to nodeID, reporting
// whether one existed.
func (hs *handshakeState) takePending(nodeID, peerID uint32) bool {
	sh := &hs.shards[handshakeShardIdx(nodeID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	pending := sh.pending[nodeID]
	if _, found := pending[peerID]; !found {
		return false
	}
	delete(pending, peerID)
	if len(pending) == 0 {
		delete(sh.pending, nodeID)
	}
	return true
}

// appendResponse queues a handshake response for peerID to collect.
func (hs *handshakeState) appendResponse(peerID uint32, msg *HandshakeResponseMsg) {
	sh := &hs.shards[handshakeShardIdx(peerID)]
	sh.mu.Lock()
	sh.responses[peerID] = append(sh.responses[peerID], msg)
	sh.mu.Unlock()
}

// snapshot copies every shard's inboxes for serialisation. Returns nil maps
// when empty, matching the pre-shard behaviour.
func (hs *handshakeState) snapshot() (
	inbox map[uint32][]*HandshakeRelayMsg,
	responses map[uint32][]*HandshakeResponseMsg,
) {
	for i := range hs.shards {
		sh := &hs.shards[i]
		sh.mu.Lock()
		for id, msgs := range sh.inbox {
			if inbox == nil {
				inbox = make(map[uint32][]*HandshakeRelayMsg)
			}
			inbox[id] = msgs
		}
		for id, msgs := range sh.responses {
			if responses == nil {
				responses = make(map[uint32][]*HandshakeResponseMsg)
			}
			responses[id] = msgs
		}
		sh.mu.Unlock()
	}
	return inbox, responses
}

// restore loads snapshotted inboxes, rebuilding pending state from the
// restored requests. Call before serving.
func (hs *handshakeState) restore(
	inbox map[uint32][]*HandshakeRelayMsg,
	responses map[uint32][]*HandshakeResponseMsg,
) {
	for id, msgs := range inbox {
		sh := &hs.shards[handshakeShardIdx(id)]
		sh.mu.Lock()
		sh.inbox[id] = msgs
		for _, msg := range msgs {
			if sh.pending[id] == nil {
				sh.pending[id] = make(map[uint32]struct{})
			}
			sh.pending[id][msg.FromNodeID] = struct{}{}
		}
		sh.mu.Unlock()
	}
	for id, msgs := range responses {
		sh := &hs.shards[handshakeShardIdx(id)]
		sh.mu.Lock()
		sh.responses[id] = msgs
		sh.mu.Unlock()
	}
}

// size totals pending requests and responses across shards, for metrics.
func (hs *handshakeState) size() (requests, responses int) {
	for i := range hs.shards {
		sh := &hs.shards[i]
		sh.mu.Lock()
		for _, msgs := range sh.inbox {
			requests += len(msgs)
		}
		for _, msgs := range sh.responses {
			responses += len(msgs)
		}
		sh.mu.Unlock()
	}
	return requests, responses
}
