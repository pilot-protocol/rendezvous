// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"log/slog"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/common/reqsig"
)

// verifyOnlineWindow is how recently a node must have heartbeated for the
// verification endpoint to report it online: three missed 60s heartbeats.
// Deliberately NOT StaleNodeThreshold (default 30 min) — that threshold
// answers "should the reaper delete this node", not "is this node
// responsive right now".
const verifyOnlineWindow = 180 * time.Second

// VerifyResponse is the JSON payload returned by POST /api/v1/verify.
// On any failure (parse, freshness, lookup, key expiry, signature) the
// response is UNIFORM: valid=false with every other field zeroed except the
// signed negative verdict — no distinction between unknown-node, reaped,
// bad-signature, and expired-key, so the endpoint is not an existence oracle.
type VerifyResponse struct {
	Valid              bool   `json:"valid"`
	Online             bool   `json:"online"`
	NetworkMember      bool   `json:"network_member"`
	Address            string `json:"address,omitempty"`
	LastSeen           string `json:"last_seen,omitempty"`
	Nonce              string `json:"nonce,omitempty"`
	LastSeenUnix       int64  `json:"last_seen_unix"`
	KeyGeneration      int64  `json:"key_generation"`
	StaleThresholdSecs int64  `json:"stale_threshold_secs"`
	Verdict            string `json:"verdict,omitempty"`
	VerdictSig         string `json:"verdict_sig,omitempty"`
	VerdictKid         string `json:"verdict_kid,omitempty"`
}

// VerifyRequest verifies an external request-signature envelope (reqsig
// canonical form) plus its base64 Ed25519 signature against the registry's
// node table and returns a registry-signed verdict. Safe for concurrent use.
func (s *Server) VerifyRequest(canonical, sigB64 string) VerifyResponse {
	now := s.now()
	s.metrics.RequestsTotal.WithLabel("verify").Inc()

	// fail returns the uniform valid:false response. The failure kind is
	// tracked only in the labeled error counter (pilot_errors_total) —
	// nothing in the response body distinguishes the cases.
	fail := func(kind string, network uint16, node uint32) VerifyResponse {
		s.metrics.ErrorsTotal.WithLabel("verify_" + kind).Inc()
		resp := VerifyResponse{}
		s.signVerdict(&resp, reqsig.Verdict{
			EnvHash:    reqsig.HashEnvelope(canonical),
			Network:    network,
			Node:       node,
			VerifiedAt: now.Unix(),
		})
		return resp
	}

	e, err := reqsig.Parse(canonical)
	if err != nil {
		return fail("parse", 0, 0)
	}
	if err := reqsig.CheckFresh(e, now, 0); err != nil {
		return fail("stale_envelope", e.Network, e.Node)
	}

	// Phase 1: snapshot node fields under the read lock. No signature
	// verification while holding s.mu — see the lock-ordering invariants
	// in server.go.
	s.mu.RLock()
	node, ok := s.nodes[e.Node]
	var pubKey []byte
	var networks []uint16
	var keyExpiresAt time.Time
	var rotateCount int
	if ok {
		pubKey = append([]byte(nil), node.PublicKey...)
		networks = append([]uint16(nil), node.Networks...)
		keyExpiresAt = node.KeyMeta.ExpiresAt
		rotateCount = node.KeyMeta.RotateCount
	}
	s.mu.RUnlock()

	if !ok {
		return fail("unknown_node", e.Network, e.Node)
	}
	// Expired keys block heartbeats (see directory.HandleHeartbeat) —
	// mirror that here: a signature from an expired key proves nothing.
	if !keyExpiresAt.IsZero() && keyExpiresAt.Before(now) {
		return fail("expired_key", e.Network, e.Node)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fail("bad_node_key", e.Network, e.Node)
	}

	// Phase 2: Ed25519 verification outside every lock.
	if _, err := reqsig.Verify(ed25519.PublicKey(pubKey), canonical, sigB64); err != nil {
		return fail("bad_signature", e.Network, e.Node)
	}

	lastSeen := node.GetLastSeen() // atomic accessor — safe without locks
	online := !lastSeen.IsZero() && now.Sub(lastSeen) <= verifyOnlineWindow
	member := false
	for _, netID := range networks {
		if netID == e.Network {
			member = true
			break
		}
	}
	var lastSeenUnix int64
	if !lastSeen.IsZero() && lastSeen.Unix() > 0 {
		lastSeenUnix = lastSeen.Unix()
	}

	resp := VerifyResponse{
		Valid:              true,
		Online:             online,
		NetworkMember:      member,
		Address:            protocol.Addr{Network: e.Network, Node: e.Node}.String(),
		Nonce:              e.Nonce,
		LastSeenUnix:       lastSeenUnix,
		KeyGeneration:      int64(rotateCount),
		StaleThresholdSecs: int64(s.StaleNodeThreshold() / time.Second),
	}
	if lastSeenUnix > 0 {
		resp.LastSeen = lastSeen.UTC().Format(time.RFC3339)
	}
	s.signVerdict(&resp, reqsig.Verdict{
		EnvHash:       reqsig.HashEnvelope(canonical),
		Network:       e.Network,
		Node:          e.Node,
		Valid:         true,
		Online:        online,
		NetworkMember: member,
		LastSeenUnix:  lastSeenUnix,
		KeyGeneration: int64(rotateCount),
		VerifiedAt:    now.Unix(),
	})
	return resp
}

// signVerdict signs v with the verdict key and fills the verdict fields on
// resp. A signing failure leaves the fields empty — the boolean answer still
// stands, callers just cannot forward it as offline proof.
func (s *Server) signVerdict(resp *VerifyResponse, v reqsig.Verdict) {
	s.initVerdictKey()
	if s.verdictPriv == nil {
		return
	}
	canon, sig, err := reqsig.SignVerdict(s.verdictPriv, v)
	if err != nil {
		slog.Warn("verdict signing failed", "err", err)
		return
	}
	resp.Verdict = canon
	resp.VerdictSig = sig
	resp.VerdictKid = s.verdictKid
}
