// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authz provides authorization and signature-verification helpers
// for the registry server (R3.1 of the registry decomposition plan).
//
// Checker holds the admin/dashboard token configuration and exposes
// gate-checking methods that were previously inline on Server. Functions
// that need network or node data accept narrow reader interfaces rather
// than coupling to Server internals, keeping authz free of circular imports.
package authz

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/common/crypto"
)

// Role is a member's permission level within a network. Values match the
// string constants used throughout the registry.
type Role = string

const (
	RoleOwner  Role = "owner"  // created the network, full control
	RoleAdmin  Role = "admin"  // can invite, remove members, change settings
	RoleMember Role = "member" // can communicate, cannot manage
)

// NetworkReader is the minimal read-only view over network state that the
// authorization helpers need.  Server implements this directly; tests can
// supply a lightweight stub.
type NetworkReader interface {
	// GetNetworkAdminToken returns the per-network admin token and whether
	// the network exists.
	GetNetworkAdminToken(netID uint16) (adminToken string, ok bool)

	// GetMemberRole returns the role for nodeID in netID and whether it exists.
	GetMemberRole(netID uint16, nodeID uint32) (role Role, ok bool)

	// IsEnterpriseNetwork returns true when netID is an enterprise network.
	IsEnterpriseNetwork(netID uint16) (enterprise bool, ok bool)
}

// NodeReader is the minimal read-only view over node state that
// IsEnterpriseNode needs.
type NodeReader interface {
	// GetNodeNetworks returns the network IDs the node belongs to and
	// whether the node exists.
	GetNodeNetworks(nodeID uint32) (netIDs []uint16, ok bool)
}

// Checker holds token configuration and exposes authorization gate methods.
type Checker struct {
	adminToken     string
	dashboardToken string
}

// NewChecker returns a Checker configured with the given tokens.
// Either token may be empty to disable the corresponding gate.
func NewChecker(adminToken, dashboardToken string) *Checker {
	return &Checker{
		adminToken:     adminToken,
		dashboardToken: dashboardToken,
	}
}

// AdminToken returns the admin token stored in this Checker.
// Used by callers that need to copy it before releasing a lock (e.g.
// Server.requireAdminToken).
func (c *Checker) AdminToken() string { return c.adminToken }

// DashboardToken returns the dashboard token stored in this Checker.
func (c *Checker) DashboardToken() string { return c.dashboardToken }

// SetAdminToken replaces the admin token.  Not safe for concurrent use;
// call only at configuration time before the server is serving requests.
func (c *Checker) SetAdminToken(t string) { c.adminToken = t }

// SetDashboardToken replaces the dashboard token.
func (c *Checker) SetDashboardToken(t string) { c.dashboardToken = t }

// RequireAdminToken validates the "admin_token" field in msg against the
// stored admin token. Returns a non-nil error when the token is absent,
// incorrect, or the checker has no admin token configured.
//
// The caller should copy c.AdminToken() under the server mutex before
// calling if concurrent updates to the token are possible.
func (c *Checker) RequireAdminToken(msg map[string]interface{}) error {
	return c.checkAdminToken(msg, c.adminToken)
}

// RequireAdminTokenWith is like RequireAdminToken but uses the supplied
// pre-copied token value.  Use this variant when the caller already holds
// a read lock and has copied the token, avoiding a second lock acquisition.
func (c *Checker) RequireAdminTokenWith(msg map[string]interface{}, adminToken string) error {
	return c.checkAdminToken(msg, adminToken)
}

// CheckAdminToken returns nil when msg carries a valid admin token, or a
// descriptive error otherwise.  It is the core helper used by both
// RequireAdminToken and RequireAdminTokenWith.
func (c *Checker) CheckAdminToken(msg map[string]interface{}) bool {
	return c.checkAdminToken(msg, c.adminToken) == nil
}

// checkAdminToken is the internal implementation shared by all public variants.
func (c *Checker) checkAdminToken(msg map[string]interface{}, adminToken string) error {
	if adminToken == "" {
		return fmt.Errorf("network creation is disabled")
	}
	token, _ := msg["admin_token"].(string)
	if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
		return fmt.Errorf("invalid admin token")
	}
	return nil
}

// RequireNetworkRole checks whether the request is authorized to act in
// netID with one of allowedRoles.  Authorization succeeds when any of the
// following holds:
//
//  1. The global admin token in msg is valid.
//  2. The per-network admin token in msg matches the network's AdminToken.
//  3. The requesting node (identified by msg["node_id"]) has one of
//     allowedRoles in netID according to nr.
//
// nr must not be nil.
func (c *Checker) RequireNetworkRole(msg map[string]interface{}, netID uint16, nr NetworkReader, allowedRoles ...Role) error {
	// 1. Global admin token always authorizes.
	if c.RequireAdminToken(msg) == nil {
		return nil
	}

	// 2. Per-network admin token.
	token, _ := msg["admin_token"].(string)
	networkAdminToken, ok := nr.GetNetworkAdminToken(netID)
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if networkAdminToken != "" && token != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(networkAdminToken)) == 1 {
			return nil
		}
	}

	// 3. RBAC role check.
	nodeID := jsonUint32(msg, "node_id")
	if nodeID == 0 {
		return fmt.Errorf("rbac: node_id required for role-based authorization")
	}
	role, hasRole := nr.GetMemberRole(netID, nodeID)
	if !hasRole {
		return fmt.Errorf("rbac: node %d has no role in network %d", nodeID, netID)
	}
	for _, allowed := range allowedRoles {
		if role == allowed {
			return nil
		}
	}
	return fmt.Errorf("rbac: node %d has role %q, requires one of %v", nodeID, role, allowedRoles)
}

// RequireEnterprise returns nil when netID is an enterprise network, or a
// clear error otherwise.  nr must not be nil.
func (c *Checker) RequireEnterprise(netID uint16, nr NetworkReader) error {
	enterprise, ok := nr.IsEnterpriseNetwork(netID)
	if !ok {
		return fmt.Errorf("network %d: %w", netID, protocol.ErrNetworkNotFound)
	}
	if !enterprise {
		return fmt.Errorf("enterprise feature: requires enterprise network")
	}
	return nil
}

// IsEnterpriseNode returns true when nodeID belongs to at least one
// enterprise network.  Both nr (NetworkReader) and nodes (NodeReader) must
// not be nil.
func (c *Checker) IsEnterpriseNode(nodeID uint32, nodes NodeReader, nr NetworkReader) bool {
	netIDs, ok := nodes.GetNodeNetworks(nodeID)
	if !ok {
		return false
	}
	for _, netID := range netIDs {
		if enterprise, ok := nr.IsEnterpriseNetwork(netID); ok && enterprise {
			return true
		}
	}
	return false
}

// VerifyNodeSignature verifies a registry write operation signature.
// pubKey is the node's stored Ed25519 public key; adminToken is a
// pre-copied value of the global admin token (copy it before releasing
// the server mutex).  msg must contain a "signature" field (base64).
// challenge is the pre-image string that was signed.
const (
	sigCacheShardCount = 64
	sigCacheShardCap   = 8192
)

type sigCacheShard struct {
	mu sync.Mutex
	m  map[[32]byte]struct{}
}

var sigCacheShards [sigCacheShardCount]sigCacheShard

func VerifyCached(pubKey, message, sig []byte) bool {
	h := sha256.New()
	h.Write(pubKey)
	h.Write(message)
	h.Write(sig)
	var key [32]byte
	h.Sum(key[:0])
	sh := &sigCacheShards[key[0]%sigCacheShardCount]
	sh.mu.Lock()
	_, hit := sh.m[key]
	sh.mu.Unlock()
	if hit {
		return true
	}
	if !crypto.Verify(pubKey, message, sig) {
		return false
	}
	sh.mu.Lock()
	if sh.m == nil || len(sh.m) >= sigCacheShardCap {
		sh.m = make(map[[32]byte]struct{}, sigCacheShardCap)
	}
	sh.m[key] = struct{}{}
	sh.mu.Unlock()
	return true
}

func VerifyNodeSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	if pubKey == nil {
		// No key on file — fall back to admin token auth.
		if err := verifyCheckAdminToken(msg, adminToken); err != nil {
			return fmt.Errorf("node has no public key: signature or admin token required")
		}
		return nil
	}
	sigB64, _ := msg["signature"].(string)
	if sigB64 == "" {
		return fmt.Errorf("signature required for authenticated node")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	ok := VerifyCached(pubKey, []byte(challenge), sig)
	if fn := loadSigVerifyHook(); fn != nil {
		fn(ok)
	}
	if !ok {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// onSigVerify is an atomic.Pointer holding the optional metrics hook
// invoked once per crypto.Verify call. atomic.Pointer makes the
// publish-once / read-many pattern race-free without a mutex on the
// hot path. The admin-token fallback path is intentionally not
// counted — the metric tracks signature-verify success rate, not
// "did the caller authenticate by any means."
var onSigVerify atomic.Pointer[func(bool)]

// SetOnSignatureVerify installs the package-level hook fired by every
// VerifyNodeSignature / VerifyHeartbeatSignature call that exercises
// crypto.Verify. Pass nil to clear. Safe to call concurrently from
// multiple Server instances in test (atomic-stored pointer).
//
// Wired from package server (server_lifecycle.go) to increment the
// pilot_signature_verify_total{result=...} counter. Kept as a
// package-level hook so authz/ stays free of a metrics import.
func SetOnSignatureVerify(fn func(bool)) {
	if fn == nil {
		onSigVerify.Store(nil)
		return
	}
	onSigVerify.Store(&fn)
}

func loadSigVerifyHook() func(bool) {
	if p := onSigVerify.Load(); p != nil {
		return *p
	}
	return nil
}

// VerifyHeartbeatSignature is an alias for VerifyNodeSignature with a
// caller-supplied adminToken (copied before releasing a read lock).
// This is the variant hot-path heartbeat handlers use when they have
// already snapshot-copied node fields.
func VerifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error {
	return VerifyNodeSignature(pubKey, adminToken, msg, challenge)
}

// verifyCheckAdminToken is a package-internal token check that does not
// require a Checker instance — used only by the signature-fallback path.
func verifyCheckAdminToken(msg map[string]interface{}, adminToken string) error {
	if adminToken == "" {
		return fmt.Errorf("network creation is disabled")
	}
	token, _ := msg["admin_token"].(string)
	if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
		return fmt.Errorf("invalid admin token")
	}
	return nil
}

// jsonUint32 extracts a uint32 from a JSON-decoded map. JSON numbers are
// float64; values outside [0, MaxUint32] return 0.
func jsonUint32(msg map[string]interface{}, key string) uint32 {
	if v, ok := msg[key].(float64); ok {
		if v < 0 || v > float64(^uint32(0)) {
			return 0
		}
		return uint32(v)
	}
	return 0
}
