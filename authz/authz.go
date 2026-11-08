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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
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

// NodeKeyReader is the optional view over node state that the RBAC path of
// RequireNetworkRole uses to authenticate the claimed node_id. A
// NetworkReader that does not also implement it has no keys to offer, so
// every role claim made through it is refused.
type NodeKeyReader interface {
	// GetNodePublicKey returns the Ed25519 public key registered for
	// nodeID. ok is false when the node is unknown or has no key.
	GetNodePublicKey(nodeID uint32) (pubKey []byte, ok bool)
}

// Checker holds token configuration and exposes authorization gate methods.
type Checker struct {
	adminToken     string
	dashboardToken string

	// allowUnsignedRole is the migration escape hatch for RequireNetworkRole
	// (see SetAllowUnsignedNetworkRole). roleSigned is its ratchet: node IDs
	// that have presented a valid role signature since this process started.
	allowUnsignedRole atomic.Bool
	roleSigned        sync.Map // uint32 -> struct{}
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

// SetAllowUnsignedNetworkRole toggles the migration escape hatch for the
// RBAC path of RequireNetworkRole. Off (the default), a role claim must be
// signed by the claimed node's registered key. On, an unsigned claim is
// honored as it was before signatures were required — which means anyone
// who can reach the registry can act as any network owner — except for
// nodes that have already presented a valid role signature to this process.
// A signature that is present is always verified, in either mode.
func (c *Checker) SetAllowUnsignedNetworkRole(enabled bool) {
	c.allowUnsignedRole.Store(enabled)
}

// AllowUnsignedNetworkRole reports whether the escape hatch is on.
func (c *Checker) AllowUnsignedNetworkRole() bool {
	return c.allowUnsignedRole.Load()
}

// RequireNetworkRole checks whether the request is authorized to act in
// netID with one of allowedRoles.  Authorization succeeds when any of the
// following holds:
//
//  1. The global admin token in msg is valid.
//  2. The per-network admin token in msg matches the network's AdminToken.
//  3. The requesting node (identified by msg["node_id"]) proves it is that
//     node — msg["signature"] is a valid Ed25519 signature by the node's
//     registered key over NetworkRoleChallenge(msg, nodeID, netID) — and
//     has one of allowedRoles in netID according to nr.
//
// Nothing on the accept/dispatch path binds a connection to a node, so
// node_id alone is a claim, not an identity. A node with no registered key
// cannot use path 3 and needs an admin token.
//
// nr must not be nil. It must also implement NodeKeyReader for path 3 to
// succeed.
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
	if err := c.verifyRoleClaim(msg, netID, nodeID, nr); err != nil {
		return err
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

// verifyRoleClaim authenticates the node_id claimed on the RBAC path.
func (c *Checker) verifyRoleClaim(msg map[string]interface{}, netID uint16, nodeID uint32, nr NetworkReader) error {
	var pubKey []byte
	if kr, ok := nr.(NodeKeyReader); ok {
		pubKey, _ = kr.GetNodePublicKey(nodeID)
	}
	msgType, _ := msg["type"].(string)

	if sigB64, _ := msg["signature"].(string); sigB64 == "" {
		if c.allowUnsignedRole.Load() {
			if _, signed := c.roleSigned.Load(nodeID); !signed {
				slog.Warn("UNSIGNED network role claim accepted (-allow-unsigned-network-role-auth is on)",
					"type", msgType, "node_id", nodeID, "network_id", netID)
				return nil
			}
		}
		if len(pubKey) == 0 {
			return fmt.Errorf("rbac: node %d has no public key: admin token required", nodeID)
		}
		return fmt.Errorf("rbac: signature required to act as node %d (update the client, or use an admin token)", nodeID)
	}

	if len(pubKey) == 0 {
		return fmt.Errorf("rbac: node %d has no public key: admin token required", nodeID)
	}
	if err := VerifyNodeSignature(pubKey, "", msg, NetworkRoleChallenge(msg, nodeID, netID)); err != nil {
		return err
	}
	c.roleSigned.Store(nodeID, struct{}{})
	return nil
}

// NetworkRoleChallenge returns the string a node signs to exercise its
// network role for the operation in msg. It binds the operation (msg
// "type"), the acting node, the network and the operation's argument, so a
// signature authorizes exactly one request shape:
//
//	delete_network:<node>:<net>
//	rename_network:<node>:<net>:<name>
//	kick_member:<node>:<net>:<target_node_id>
//	promote_member:<node>:<net>:<target_node_id>
//	demote_member:<node>:<net>:<target_node_id>
//	transfer_ownership:<node>:<net>:<new_owner_id>
//	set_member_tags:<node>:<net>:<target_node_id>:<hex sha256 of tags joined by ",">
//	set_network_policy:<node>:<net>:<hex sha256 of NetworkPolicyDigestInput>
//	set_expr_policy:<node>:<net>:<hex sha256 of the expr_policy string>
//
// Any other type signs "<type>:<node>:<net>". The registry client in
// common/registry/client builds the same strings; the two are pinned to
// each other by golden vectors in both modules.
func NetworkRoleChallenge(msg map[string]interface{}, nodeID uint32, netID uint16) string {
	msgType, _ := msg["type"].(string)
	base := fmt.Sprintf("%s:%d:%d", msgType, nodeID, netID)
	switch msgType {
	case "rename_network":
		name, _ := msg["name"].(string)
		return base + ":" + name
	case "kick_member", "promote_member", "demote_member":
		return fmt.Sprintf("%s:%d", base, jsonUint32(msg, "target_node_id"))
	case "transfer_ownership":
		return fmt.Sprintf("%s:%d", base, jsonUint32(msg, "new_owner_id"))
	case "set_member_tags":
		var tags []string
		if raw, ok := msg["tags"].([]interface{}); ok {
			for _, rt := range raw {
				if t, ok := rt.(string); ok {
					tags = append(tags, t)
				}
			}
		}
		return fmt.Sprintf("%s:%d:%s", base, jsonUint32(msg, "target_node_id"), hexSHA256(strings.Join(tags, ",")))
	case "set_network_policy":
		return base + ":" + hexSHA256(NetworkPolicyDigestInput(msg))
	case "set_expr_policy":
		var expr string
		switch v := msg["expr_policy"].(type) {
		case string:
			expr = v
		case map[string]interface{}:
			b, _ := json.Marshal(v)
			expr = string(b)
		}
		return base + ":" + hexSHA256(expr)
	}
	return base
}

// NetworkPolicyDigestInput is the canonical form of the three fields a
// set_network_policy request may carry, as decoded from JSON. An absent
// field is "-"; a present one is "=" followed by its value, so a signature
// over "leave description alone" cannot be replayed as "clear it".
func NetworkPolicyDigestInput(msg map[string]interface{}) string {
	maxMembers := "-"
	if v, ok := msg["max_members"].(float64); ok {
		maxMembers = "=" + strconv.FormatFloat(v, 'f', -1, 64)
	}
	ports := "-"
	if v, ok := msg["allowed_ports"].([]interface{}); ok {
		parts := make([]string, len(v))
		for i, p := range v {
			if f, ok := p.(float64); ok {
				parts[i] = strconv.FormatFloat(f, 'f', -1, 64)
			} else {
				parts[i] = "?"
			}
		}
		ports = "=" + strings.Join(parts, ",")
	}
	description := "-"
	if v, ok := msg["description"].(string); ok {
		description = "=" + v
	}
	return "max_members" + maxMembers + "\nallowed_ports" + ports + "\ndescription" + description
}

func hexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
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
