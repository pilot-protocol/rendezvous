// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	identpkg "github.com/pilot-protocol/rendezvous/identity"
	walpkg "github.com/pilot-protocol/rendezvous/wal"
)

// ConnCount returns the current number of active connections (for testing).
func (s *Server) ConnCount() int64 {
	return s.accept.ConnCount()
}

// Reap triggers stale node and beacon cleanup (for testing).
func (s *Server) Reap() {
	s.reapStaleNodes()
	s.reapStaleBeacons()
}

// PromoteToPrimary increments the replication term and persists it, fencing
// off a stale former primary. Safe to call on any server that should become
// the sole write master. (PILOT-328)
func (s *Server) PromoteToPrimary() error {
	s.mu.Lock()
	s.term++
	newTerm := s.term
	s.mu.Unlock()
	slog.Warn("replication: server promoted to primary", "term", newTerm)
	return s.flushSave()
}

// Term returns the current replication epoch.
func (s *Server) Term() uint64 {
	s.mu.RLock()
	t := s.term
	s.mu.RUnlock()
	return t
}

// ── Dispatcher interface implementation ───────────────────────────────────────
//
// These methods satisfy accept.Dispatcher so that Acceptor can delegate all
// domain logic back to Server without importing the server package (avoiding
// the import cycle). The accept layer owns the TCP framing; Server owns the
// business logic.

// HandleMessage satisfies accept.Dispatcher. It dispatches a decoded JSON
// message and returns the response map.
func (s *Server) HandleMessage(msg map[string]interface{}, remoteAddr string) (map[string]interface{}, error) {
	return s.handleMessage(msg, remoteAddr)
}

// HandleSubscribeReplication satisfies accept.Dispatcher. It takes over the
// conn for replication streaming.
func (s *Server) HandleSubscribeReplication(conn net.Conn) {
	s.handleSubscribeReplication(conn)
}

// HandleBinaryHeartbeat satisfies accept.Dispatcher.
func (s *Server) HandleBinaryHeartbeat(conn net.Conn, payload []byte) {
	s.handleBinaryHeartbeat(conn, payload)
}

// HandleBinaryLookup satisfies accept.Dispatcher.
func (s *Server) HandleBinaryLookup(conn net.Conn, payload []byte, host string) {
	s.handleBinaryLookup(conn, payload, host)
}

// HandleBinaryResolve satisfies accept.Dispatcher.
func (s *Server) HandleBinaryResolve(conn net.Conn, payload []byte, host string) {
	s.handleBinaryResolve(conn, payload, host)
}

// ReplicationToken satisfies accept.Dispatcher. Returns the current replication
// auth token; empty string means replication is disabled.
// Delegated to walStore (R6.1).
func (s *Server) ReplicationToken() string {
	return s.walStore.ReplicationToken()
}

// AddRequest satisfies accept.Dispatcher. Increments the server-level request counter.
func (s *Server) AddRequest() {
	s.requestCount.Add(1)
}

// handleBinaryHeartbeat processes a native binary heartbeat request.
// handleBinaryHeartbeat delegates to the directory sub-package (R4.2).
func (s *Server) handleBinaryHeartbeat(conn net.Conn, payload []byte) {
	s.directory.HandleBinaryHeartbeat(conn, payload)
}

// handleBinaryLookup delegates to the directory sub-package (R4.2).
func (s *Server) handleBinaryLookup(conn net.Conn, payload []byte, host string) {
	s.directory.HandleBinaryLookup(conn, payload)
}

// handleBinaryResolve delegates to the directory sub-package (R4.2).
func (s *Server) handleBinaryResolve(conn net.Conn, payload []byte, host string) {
	s.directory.HandleBinaryResolve(conn, payload)
}

func (s *Server) handleMessage(msg map[string]interface{}, remoteAddr string) (resp map[string]interface{}, err error) {
	s.requestCount.Add(1)
	msgType, _ := msg["type"].(string)

	// Per-network request counting: if the message identifies a node, increment its networks' counters.
	if nodeIDVal, ok := msg["node_id"]; ok {
		var nodeID uint32
		switch v := nodeIDVal.(type) {
		case float64:
			nodeID = uint32(v)
		case uint32:
			nodeID = v
		}
		if nodeID > 0 {
			s.mu.RLock()
			if node, exists := s.nodes[nodeID]; exists {
				nets := node.Networks
				for _, netID := range nets {
					if net, ok := s.networks[netID]; ok {
						net.RequestCount.Add(1)
					}
				}
			}
			s.mu.RUnlock()
		}
	}

	// Prometheus instrumentation
	s.metrics.RequestsTotal.WithLabel(msgType).Inc()
	start := time.Now()
	defer func() {
		s.metrics.RequestDuration.WithLabel(msgType).Observe(time.Since(start).Seconds())
		if err != nil {
			s.metrics.ErrorsTotal.WithLabel(msgType).Inc()
		}
	}()

	// Standby mode: reject write operations, allow reads
	s.mu.RLock()
	isStandby := s.walStore.IsStandby()
	s.mu.RUnlock()
	if isStandby {
		switch msgType {
		case "lookup", "resolve", "list_networks", "list_nodes", "heartbeat", "poll_handshakes", "poll_invites", "resolve_hostname", "beacon_list",
			"get_key_info", "get_network_policy", "get_audit_log", "get_member_role", "check_trust",
			"get_webhook", "get_audit_export", "get_webhook_dlq", "get_identity", "get_idp_config", "get_provision_status",
			"get_expr_policy", "get_member_tags", "directory_status":
			// reads are allowed on standby
		default:
			return nil, fmt.Errorf("standby mode: write operations not accepted (use primary)")
		}
	}

	// Dispatch via the registration-table lookup in dispatch.go.
	// The unknown-type error path uses the same %q-quoted message
	// as the historical switch this replaced.
	h, ok := handlers[msgType]
	if !ok {
		return nil, fmt.Errorf("unknown message type: %q", msgType)
	}

	// Breaker gate: consult the named breaker for this msgType (if any
	// is mapped). Open returns an error to the caller and skips the
	// handler entirely so the gated surface stays cold for as long as
	// the breaker holds. Closed / HalfOpen / unmapped types all pass
	// through. HalfOpen surfaces as a debug log only (don't spam at
	// info — half_open is meant to ride on operator observation, not
	// produce noise per request).
	if bname, gated := breakerForType[msgType]; gated && s.breakers != nil {
		allow, state := s.breakers.Allow(bname)
		if !allow {
			reason := s.breakers.Reason(bname)
			s.metrics.ErrorsTotal.WithLabel(msgType + ":breaker_open").Inc()
			if reason != "" {
				return nil, fmt.Errorf("service unavailable: breaker %q is open (%s)", bname, reason)
			}
			return nil, fmt.Errorf("service unavailable: breaker %q is open", bname)
		}
		if state.String() == "half_open" {
			slog.Debug("registry breaker half_open", "breaker", bname, "type", msgType, "remote_addr", remoteAddr)
		}
	}

	// Per-request panic boundary: a panicking handler must not crash
	// the registry process — registries serve the entire fleet, so
	// "one bad request" cannot be a DoS vector. Convert the panic to
	// a normal error; the offending caller gets an error response,
	// every other in-flight request is unaffected. The metric defer
	// above still fires (it runs LIFO after this defer); ErrorsTotal
	// gets incremented via the err != nil branch.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("registry handler panic recovered: type=%q panic=%v", msgType, r)
			resp = nil
			s.metrics.ErrorsTotal.WithLabel(msgType + ":panic").Inc()
			slog.Error("registry handler panicked",
				"type", msgType,
				"panic", fmt.Sprintf("%v", r),
				"remote_addr", remoteAddr,
				"stack", string(debug.Stack()),
			)
		}
	}()

	resp, err = h(s, msg, remoteAddr)
	// common@v0.4.7 (PILOT-132): registry client rejects non-empty
	// responses missing a "type" envelope field. Echo the request type
	// back so every handler doesn't have to remember to set it. A
	// handler that explicitly sets "type" still wins.
	if err == nil && len(resp) > 0 {
		if _, hasType := resp["type"]; !hasType {
			resp["type"] = msgType
		}
	}
	return resp, err
}

// --- routing.PunchBackend implementation ---
//
// These methods satisfy routing.PunchBackend so routing.Store can call back
// into the server for node lookups without importing the server package.

// NodePubKeyAndAdminToken returns the public key and admin token for the given
// node. Implements routing.PunchBackend.
func (s *Server) NodePubKeyAndAdminToken(nodeID uint32) (pubKey []byte, adminToken string, ok bool) {
	s.mu.RLock()
	node, exists := s.nodes[nodeID]
	if !exists {
		s.mu.RUnlock()
		return nil, "", false
	}
	pubKey = node.PublicKey
	adminToken = s.authz.AdminToken()
	s.mu.RUnlock()
	return pubKey, adminToken, true
}

// VerifyPunchSignature verifies the Ed25519 (or admin-token fallback) signature
// on a punch message. Implements routing.PunchBackend.
func (s *Server) VerifyPunchSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	return s.verifyHeartbeatSignature(pubKey, adminToken, msg, challenge)
}

// NodeAddrs returns the RealAddr of nodeA and nodeB using shard locks.
// Implements routing.PunchBackend.
func (s *Server) NodeAddrs(nodeA, nodeB uint32) (addrA string, okA bool, addrB string, okB bool) {
	s.mu.RLock()
	a, foundA := s.nodes[nodeA]
	b, foundB := s.nodes[nodeB]
	s.mu.RUnlock()

	if foundA {
		shA := s.nodeShard(nodeA)
		shA.RLock()
		addrA = a.RealAddr
		shA.RUnlock()
	}
	if foundB {
		shB := s.nodeShard(nodeB)
		shB.RLock()
		addrB = b.RealAddr
		shB.RUnlock()
	}
	return addrA, foundA, addrB, foundB
}

// --- Persistence ---

// TriggerSnapshot manually triggers a snapshot save. This is useful for testing
// and for ensuring data is persisted before shutdown. Returns an error if the
// save fails, or nil if there's no storePath configured.
// TriggerSnapshot manually triggers a snapshot save.
// Delegated to walStore (R6.1).
func (s *Server) TriggerSnapshot() error {
	return s.walStore.TriggerSnapshot()
}

// Snapshot serialization types — moved to the wal sub-package (R6.2).
// Type aliases keep all existing code in this file compiling unchanged.
//
// snapshot is the JSON-serializable full registry state written by flushSave
// and read by load.
type snapshot = walpkg.Snapshot

// snapshotNode is the JSON-serializable form of a single registry node.
type snapshotNode = walpkg.SnapshotNode

// snapshotNet is the JSON-serializable form of a single registry network.
type snapshotNet = walpkg.SnapshotNet

// --- trustpkg.NodeView implementation (R2.1) ---

// LookupNode satisfies trustpkg.NodeView. It returns the public key and
// network membership list for the given node. Safe for concurrent use.

func (s *Server) LookupNode(id uint32) (pubKey []byte, networks []uint16, ok bool) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	if exists {
		pubKey = node.PublicKey
		networks = append([]uint16(nil), node.Networks...)
	}
	s.mu.RUnlock()
	return pubKey, networks, exists
}

// AdminToken satisfies trustpkg.NodeView. It returns the current global
// admin token. Safe for concurrent use.
func (s *Server) AdminToken() string {
	s.mu.RLock()
	t := s.authz.AdminToken()
	s.mu.RUnlock()
	return t
}

// ---------------------------------------------------------------------------
// identpkg.NodeView implementation — satisfies identity.NodeView interface.
// These methods are called by s.identity (the identity.Store).
// ---------------------------------------------------------------------------

// LookupNodeKey satisfies identpkg.NodeView. Returns the current public key.
func (s *Server) LookupNodeKey(id uint32) (pubKey []byte, ok bool) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	if exists {
		pubKey = make([]byte, len(node.PublicKey))
		copy(pubKey, node.PublicKey)
	}
	s.mu.RUnlock()
	return pubKey, exists
}

// LookupNodeFull satisfies identpkg.NodeView. Returns identity-related fields.
func (s *Server) LookupNodeFull(id uint32) (pubKey []byte, keyMeta identpkg.KeyInfo, networks []uint16, externalID, owner string, ok bool) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	if exists {
		pubKey = make([]byte, len(node.PublicKey))
		copy(pubKey, node.PublicKey)
		keyMeta = identpkg.KeyInfo{
			CreatedAt:   node.KeyMeta.CreatedAt,
			RotatedAt:   node.KeyMeta.RotatedAt,
			RotateCount: node.KeyMeta.RotateCount,
			ExpiresAt:   node.KeyMeta.ExpiresAt,
		}
		networks = append([]uint16(nil), node.Networks...)
		externalID = node.ExternalID
		owner = node.Owner
	}
	s.mu.RUnlock()
	return pubKey, keyMeta, networks, externalID, owner, exists
}

// UpdateNodeKey satisfies identpkg.NodeView. Atomically swaps the public key
// if it still matches expectedPubKey (stale-check). Returns the old pubkey
// (base64-encoded) on success.
func (s *Server) UpdateNodeKey(id uint32, expectedPubKey, newPubKey []byte, rotatedAt time.Time) (oldPubKeyB64 string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, ok := s.nodes[id]
	if !ok {
		return "", fmt.Errorf("node %d: %w", id, protocol.ErrNodeNotFound)
	}
	if !bytes.Equal(node.PublicKey, expectedPubKey) {
		return "", identpkg.ErrKeyRotatedConcurrently
	}

	oldPubKeyB64 = crypto.EncodePublicKey(node.PublicKey)
	sh := s.nodeShard(id)
	sh.Lock()
	node.PublicKey = newPubKey
	node.SetLastSeen(rotatedAt)
	node.KeyMeta.RotatedAt = rotatedAt
	node.KeyMeta.RotateCount++
	sh.Unlock()

	return oldPubKeyB64, nil
}

// UpdateNodeKeyExpiry satisfies identpkg.NodeView. Sets/clears key expiry.
func (s *Server) UpdateNodeKeyExpiry(id uint32, expiresAt time.Time) (oldExpiry time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[id]
	if !exists {
		return time.Time{}, false
	}
	sh := s.nodeShard(id)
	sh.Lock()
	oldExpiry = node.KeyMeta.ExpiresAt
	node.KeyMeta.ExpiresAt = expiresAt
	sh.Unlock()
	return oldExpiry, true
}

// UpdateNodeExternalID satisfies identpkg.NodeView. Sets the external identity.
func (s *Server) UpdateNodeExternalID(id uint32, externalID string) (oldID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, exists := s.nodes[id]
	if !exists {
		return "", false
	}
	sh := s.nodeShard(id)
	sh.Lock()
	oldID = node.ExternalID
	node.ExternalID = externalID
	sh.Unlock()
	return oldID, true
}

// SubmitBadge satisfies identpkg.NodeView. Stores a verified-address badge.
func (s *Server) SubmitBadge(id uint32, badge, badgeSig, provider string, verifiedAt time.Time) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[id]
	if !exists {
		return false
	}
	sh := s.nodeShard(id)
	sh.Lock()
	node.Badge = badge
	node.BadgeSig = badgeSig
	node.VerificationProvider = provider
	node.VerifiedAt = verifiedAt
	sh.Unlock()
	return true
}

// SetRecoveryEnrollment satisfies identpkg.NodeView. Records the opaque
// identity commitment a future recovery must match.
func (s *Server) SetRecoveryEnrollment(id uint32, commitment, provider string) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, exists := s.nodes[id]
	if !exists {
		return false
	}
	sh := s.nodeShard(id)
	sh.Lock()
	node.RecoveryCommitment = commitment
	node.RecoveryProvider = provider
	sh.Unlock()
	return true
}

// GetRecoveryEnrollment satisfies identpkg.NodeView.
func (s *Server) GetRecoveryEnrollment(id uint32) (commitment, provider string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, exists := s.nodes[id]
	if !exists || node.RecoveryCommitment == "" {
		return "", "", false
	}
	return node.RecoveryCommitment, node.RecoveryProvider, true
}

// ForceRotateKey satisfies identpkg.NodeView. Swaps the public key WITHOUT
// an old-key stale-check — used only by identity recovery, authorized by a
// cold-key-signed recovery statement rather than the old key.
func (s *Server) ForceRotateKey(id uint32, newPubKey []byte, rotatedAt time.Time) (oldPubKeyB64 string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[id]
	if !ok {
		return "", fmt.Errorf("node %d: %w", id, protocol.ErrNodeNotFound)
	}
	oldPubKeyB64 = crypto.EncodePublicKey(node.PublicKey)
	sh := s.nodeShard(id)
	sh.Lock()
	node.PublicKey = newPubKey
	node.SetLastSeen(rotatedAt)
	node.KeyMeta.RotatedAt = rotatedAt
	node.KeyMeta.RotateCount++
	// A recovered address must NOT inherit the prior key holder's verification
	// badge: the badge may attest a different external identity than the one
	// that authorized this recovery, so the new holder must re-verify.
	node.Badge = ""
	node.BadgeSig = ""
	node.VerificationProvider = ""
	node.VerifiedAt = time.Time{}
	sh.Unlock()
	return oldPubKeyB64, nil
}

// NodeIsEnterprise satisfies identpkg.NodeView. Returns true if the node belongs
// to at least one enterprise network.
func (s *Server) NodeIsEnterprise(id uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[id]
	if !ok {
		return false
	}
	for _, netID := range node.Networks {
		if net, ok := s.networks[netID]; ok && net.Enterprise {
			return true
		}
	}
	return false
}

// CheckAdminToken satisfies identpkg.NodeView. Returns nil if the message
// carries a valid admin token.
func (s *Server) CheckAdminToken(msg map[string]interface{}) error {
	return s.requireAdminToken(msg)
}

// VerifyHeartbeatSignature satisfies identpkg.NodeView. It delegates to the
// existing server-internal signature-verification helper.
func (s *Server) VerifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	return s.verifyHeartbeatSignature(pubKey, adminToken, msg, challenge)
}

// Now satisfies identpkg.NodeView. Returns the current time via the
// server-overridable clock (supports testing).
func (s *Server) Now() time.Time {
	return s.now()
}
