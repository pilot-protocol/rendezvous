// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity implements the registry's identity, key-lifecycle, and
// identity-provider handlers.
//
// Thread safety: all exported methods are safe for concurrent use.
package identity

import (
	"bytes"
	gocrypto "crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/badgeverify"
	pilotcrypto "github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/common/registry/wire"
	"github.com/pilot-protocol/rendezvous/events"
)

// BlueprintIdentityProvider is a type alias so callers don't need to import wire.
type BlueprintIdentityProvider = wire.BlueprintIdentityProvider

// KeyRotationCallback is called after a successful key rotation so that the
// caller (Server) can update its pubKeyIdx index.
//
//	nodeID     — node whose key was rotated
//	oldPubKey  — base64-encoded old public key (key to delete from index)
//	newPubKey  — base64-encoded new public key (key to add to index)
type KeyRotationCallback func(nodeID uint32, oldPubKey, newPubKey string)

// KeyInfo mirrors server.KeyInfo; we declare it here to keep the sub-package
// independent of the parent package. The two must stay in sync.
type KeyInfo struct {
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	RotateCount int       `json:"rotate_count"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// WALRecorder is called to write a WAL entry after a key rotation.
// clearBadge is true only for recovery-driven rotations (ForceRotateKey),
// which also drop the verification badge — the WAL replay must reproduce
// that badge-clear, otherwise a crash between the WAL fsync and the next
// snapshot replays the rotation but leaves a stale badge on the new key.
type WALRecorder func(nodeID uint32, newPubKeyB64, rotatedAt string, clearBadge bool)

// ErrKeyRotatedConcurrently is returned by NodeView.UpdateNodeKey when a
// concurrent rotation landed between Phase 1 (snapshot) and Phase 3 (commit).
var ErrKeyRotatedConcurrently = fmt.Errorf("rotate_key: key rotated concurrently, retry")

// sharedHTTPClient is reused across identity webhook calls so that the
// underlying TCP connections are pooled by the transport layer.
// It disables redirects entirely (a redirect during identity webhook calls
// is a protocol anomaly and a supply-chain attack vector) and enforces a
// TLS 1.2 minimum version (PILOT-241).
var sharedHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

// jwksHTTPClient is a hardened HTTP client used ONLY for JWKS key-fetch
// (fetchJWKSKeys). It disables redirects entirely (a redirect during JWKS
// fetch is a protocol anomaly and a supply-chain attack vector) and enforces
// a TLS 1.2 minimum version.
//
// TLS certificate pinning is handled via jwksPinnedHTTPClient which returns
// a client that verifies the server's TLS certificate fingerprint against
// the configured pinned fingerprint (PILOT-241).
var jwksHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

// NodeView is the read/write interface the Store uses to access node data.
// All methods must be safe for concurrent use.
type NodeView interface {
	// LookupNodeKey returns the current public key for a node.
	// ok is false if the node does not exist.
	LookupNodeKey(id uint32) (pubKey []byte, ok bool)

	// LookupNodeFull returns full identity-related fields for a node.
	// ok is false if the node does not exist.
	LookupNodeFull(id uint32) (pubKey []byte, keyMeta KeyInfo, networks []uint16, externalID, owner string, ok bool)

	// UpdateNodeKey atomically swaps the node's public key if it still matches
	// expectedPubKey (stale-check for concurrent-rotation detection).
	// Returns the old public key (base64-encoded) and nil on success.
	// Returns ErrKeyRotatedConcurrently if the key was rotated concurrently.
	// Returns protocol.ErrNodeNotFound if the node was deregistered.
	UpdateNodeKey(id uint32, expectedPubKey, newPubKey []byte, rotatedAt time.Time) (oldPubKeyB64 string, err error)

	// UpdateNodeKeyExpiry sets/clears the key expiry for a node.
	// Returns the old expiry value. ok is false if the node does not exist.
	UpdateNodeKeyExpiry(id uint32, expiresAt time.Time) (oldExpiry time.Time, ok bool)

	// UpdateNodeExternalID sets the external identity string on a node.
	// Returns the old external ID. ok is false if the node does not exist.
	UpdateNodeExternalID(id uint32, externalID string) (oldID string, ok bool)

	// SubmitBadge stores a verified-address badge (and its signature) on a
	// node so lookups can surface verified status. ok is false if the node
	// does not exist.
	SubmitBadge(id uint32, badge, badgeSig, provider string, verifiedAt time.Time) (ok bool)

	// SetRecoveryEnrollment records the opaque identity commitment that a
	// later recovery must match. ok is false if the node does not exist.
	SetRecoveryEnrollment(id uint32, commitment, provider string) (ok bool)

	// GetRecoveryEnrollment returns the stored recovery commitment for a
	// node. ok is false if the node does not exist or is not enrolled.
	GetRecoveryEnrollment(id uint32) (commitment, provider string, ok bool)

	// ConsumeRecoveryNonce atomically records a recovery-authorization nonce
	// as consumed for a node, persisted+replicated alongside the recovery
	// commitment. It returns false (without mutating) if the SAME nonce is
	// already recorded as consumed for this node — i.e. a replay that
	// survived a restart or standby failover. ok is false if the node does
	// not exist.
	ConsumeRecoveryNonce(id uint32, nonce string, exp time.Time) (recorded, ok bool)

	// ForceRotateKey swaps a node's public key WITHOUT requiring the old
	// key — used only by identity recovery, whose authorization comes from a
	// cold-key-signed recovery statement, not the old key. Returns the old
	// public key (base64). Returns protocol.ErrNodeNotFound if absent.
	ForceRotateKey(id uint32, newPubKey []byte, rotatedAt time.Time) (oldPubKeyB64 string, err error)

	// NodeIsEnterprise returns true if the node belongs to at least one
	// enterprise-flagged network.
	NodeIsEnterprise(id uint32) bool

	// AdminToken returns the global admin token.
	AdminToken() string

	// CheckAdminToken returns nil if the message carries a valid admin token.
	CheckAdminToken(msg map[string]interface{}) error

	// VerifyHeartbeatSignature verifies a heartbeat-style Ed25519 signature.
	VerifyHeartbeatSignature(pubKey []byte, adminToken string, msg map[string]interface{}, challenge string) error

	// Now returns the current time (may be overridden in tests).
	Now() time.Time
}

// Callbacks bundles the side-effect functions the Store calls on state changes.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// Save triggers a debounced snapshot write.
	Save func()

	// Audit records an audit-log entry.
	Audit func(action string, attrs ...any)

	// IncKeyRotations increments the key-rotation counter.
	IncKeyRotations func()

	// IncIDPVerifications increments the IDP-verification counter.
	IncIDPVerifications func()

	// RecordWAL writes a key-rotation WAL entry.
	RecordWAL WALRecorder

	// OnKeyRotated is the callback that updates pubKeyIdx in the parent Server.
	OnKeyRotated KeyRotationCallback

	// Bus is the event bus used to publish "key.rotated" events.
	Bus events.Bus
}

// Store holds the mutable identity and key-lifecycle state.
//
// Lock ordering:
//
//	mu (RWMutex) — protects identityWebhookURL, idpConfig.
//	jwksCache has its own internal mutex.
//
// These are independent of the parent Server's mu. Store methods must not
// acquire the parent mutex.
type Store struct {
	nodes NodeView
	cb    Callbacks

	mu                    sync.RWMutex
	identityWebhookURL    string
	identityWebhookSecret string
	idpConfig             *BlueprintIdentityProvider
	pinnedCertFingerprint string

	jwksCache *JWKSCache

	// consumedNonces tracks recovery-authorization nonces that have already
	// been redeemed, keyed to their expiry, so a recovery statement cannot
	// be replayed. Pruned lazily on each recovery. In-memory: recovery
	// statements are minutes-lived, so a restart's replay window is bounded
	// by the statement's own exp (hardening TODO: persist via snapshot).
	nonceMu        sync.Mutex
	consumedNonces map[string]time.Time

	// Credential verifiers, indirected so tests can stub them (the real
	// ones verify against badgeverify's compiled-in pinned keyrings, which
	// hold all-zero placeholders outside a release build).
	verifyBadge      func(badge, sig string, nodeID uint32) (badgeverify.Badge, error)
	verifyEnrollment func(statement, sig string) (badgeverify.Enrollment, error)
	verifyRecovery   func(statement, sig string) (badgeverify.Recovery, error)
}

// NewStore creates an empty, ready-to-use Store.
func NewStore(nodes NodeView, cb Callbacks) *Store {
	return &Store{
		nodes:            nodes,
		cb:               cb,
		jwksCache:        NewJWKSCache(),
		consumedNonces:   make(map[string]time.Time),
		verifyBadge:      badgeverify.VerifyForNode,
		verifyEnrollment: badgeverify.VerifyEnrollment,
		verifyRecovery:   badgeverify.VerifyRecovery,
	}
}

// ---------------------------------------------------------------------------
// Identity webhook
// ---------------------------------------------------------------------------

// SetWebhookURL sets the identity verification webhook URL.
// An empty string disables identity verification.
func (st *Store) SetWebhookURL(url string) {
	st.mu.Lock()
	st.identityWebhookURL = url
	st.mu.Unlock()
	if url != "" {
		slog.Info("identity webhook configured", "url", url)
	}
}

// GetWebhookURL returns the currently configured identity webhook URL.
func (st *Store) GetWebhookURL() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.identityWebhookURL
}

// SetIdentityWebhookSecret sets the HMAC-SHA256 pre-shared secret for
// identity webhook request/response signing (PILOT-240). When non-empty,
// VerifyToken signs outbound requests and verifies response signatures.
func (st *Store) SetIdentityWebhookSecret(secret string) {
	st.mu.Lock()
	st.identityWebhookSecret = secret
	st.mu.Unlock()
}

// GetIdentityWebhookSecret returns the currently configured identity
// webhook HMAC secret.
func (st *Store) GetIdentityWebhookSecret() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.identityWebhookSecret
}

// VerifyToken sends the token to the configured identity webhook and returns
// the verified external ID. Returns ("", nil) if no webhook is configured.
//
// When a webhook secret is configured, outbound requests carry an
// X-Pilot-Signature-256 HMAC-SHA256 header, and the response MUST include
// a matching X-Pilot-Signature-256 header — unsigned responses are rejected
// (PILOT-240).
func (st *Store) VerifyToken(token string) (string, error) {
	st.mu.RLock()
	url := st.identityWebhookURL
	secret := st.identityWebhookSecret
	st.mu.RUnlock()

	if url == "" {
		return "", nil
	}
	if token == "" {
		return "", nil
	}

	body, err := json.Marshal(identityVerifyRequest{Token: token})
	if err != nil {
		return "", fmt.Errorf("marshal identity request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build identity request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// HMAC-SHA256 request signing (PILOT-240): when a secret is configured,
	// sign the request body so the webhook can verify the caller.
	if secret != "" {
		reqMac := hmac.New(sha256.New, []byte(secret))
		reqMac.Write(body)
		req.Header.Set("X-Pilot-Signature-256", hex.EncodeToString(reqMac.Sum(nil)))
	}

	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		slog.Warn("identity webhook request failed", "error", err)
		return "", fmt.Errorf("identity verification failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identity webhook returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read identity response: %w", err)
	}

	// HMAC-SHA256 response verification (PILOT-240): when a secret is
	// configured, the response MUST carry a valid X-Pilot-Signature-256
	// header. Unsigned or mis-signed responses are rejected to prevent
	// webhook-spoofing attacks.
	if secret != "" {
		respSig := resp.Header.Get("X-Pilot-Signature-256")
		if respSig == "" {
			return "", fmt.Errorf("identity webhook response missing X-Pilot-Signature-256 header")
		}
		respMac := hmac.New(sha256.New, []byte(secret))
		respMac.Write(respBody)
		expected := hex.EncodeToString(respMac.Sum(nil))
		if !hmac.Equal([]byte(respSig), []byte(expected)) {
			return "", fmt.Errorf("identity webhook response signature mismatch")
		}
	}

	var result identityVerifyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse identity response: %w", err)
	}

	if !result.Verified {
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "token not verified"
		}
		return "", fmt.Errorf("identity verification rejected: %s", errMsg)
	}

	if result.ExternalID == "" {
		return "", fmt.Errorf("identity webhook returned empty external_id")
	}

	if st.cb.IncIDPVerifications != nil {
		st.cb.IncIDPVerifications()
	}
	slog.Info("identity verified", "external_id", result.ExternalID)
	return result.ExternalID, nil
}

// ---------------------------------------------------------------------------
// IDP config
// ---------------------------------------------------------------------------

// SetIDPConfig stores the identity provider configuration.
func (st *Store) SetIDPConfig(cfg *BlueprintIdentityProvider) {
	st.mu.Lock()
	st.idpConfig = cfg
	if cfg != nil {
		st.identityWebhookURL = cfg.URL
	}
	st.mu.Unlock()
}

// GetIDPConfig returns the current identity provider configuration.
func (st *Store) GetIDPConfig() *BlueprintIdentityProvider {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.idpConfig
}

// ClearIDPConfig removes the identity provider configuration and webhook URL.
func (st *Store) ClearIDPConfig() {
	st.mu.Lock()
	st.idpConfig = nil
	st.identityWebhookURL = ""
	st.pinnedCertFingerprint = ""
	st.mu.Unlock()
}

// SetPinnedCertFingerprint sets the pinned TLS certificate fingerprint
// (SHA-256 of the DER-encoded certificate) for the IDP. When set, every
// outbound TLS connection to the identity provider will verify that the
// server's certificate matches this fingerprint (PILOT-241).
//
// The fingerprint should be specified as a lowercase hex-encoded SHA-256
// hash of the DER-encoded certificate, e.g.
// "a4b3c2d1e5f6..." (64 hex chars).
func (st *Store) SetPinnedCertFingerprint(fp string) {
	st.mu.Lock()
	st.pinnedCertFingerprint = fp
	st.mu.Unlock()
}

// GetPinnedCertFingerprint returns the currently configured pinned
// TLS certificate fingerprint, or empty string if not set.
func (st *Store) GetPinnedCertFingerprint() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.pinnedCertFingerprint
}

// ---------------------------------------------------------------------------
// Protocol handlers
// ---------------------------------------------------------------------------

// HandleRotateKey implements the "rotate_key" protocol command.
//
// 3-PHASE LOCK PATTERN (delegated through NodeView):
//
//	Phase 1: snapshot current pubkey via LookupNodeKey (under NodeView's RLock).
//	Phase 2: Ed25519 verify outside all locks (~28µs).
//	Phase 3: UpdateNodeKey re-checks pubkey and commits (under NodeView's Lock).
func (st *Store) HandleRotateKey(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")
	sigB64, _ := msg["signature"].(string)
	newPubKeyB64, _ := msg["new_public_key"].(string)

	if sigB64 == "" {
		return nil, fmt.Errorf("rotate_key requires a valid signature")
	}
	if newPubKeyB64 == "" {
		return nil, fmt.Errorf("rotate_key requires new_public_key")
	}

	newPubKey, err := pilotcrypto.DecodePublicKey(newPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid new_public_key: %w", err)
	}

	// Phase 1 — snapshot current pubkey (under RLock inside LookupNodeKey).
	currentPubKey, ok := st.nodes.LookupNodeKey(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	// Phase 2 — verify outside the lock (~28µs Ed25519).
	challenge := fmt.Sprintf("rotate:%d:%s", nodeID, newPubKeyB64)
	sig, err := base64Decode(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !pilotcrypto.Verify(currentPubKey, []byte(challenge), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Phase 3 — commit via NodeView.UpdateNodeKey with stale-key re-check.
	rotatedAt := st.nodes.Now()
	oldPubKeyB64, err := st.nodes.UpdateNodeKey(nodeID, currentPubKey, newPubKey, rotatedAt)
	if err != nil {
		return nil, err // ErrNodeNotFound or ErrKeyRotatedConcurrently
	}

	// Update pubKeyIdx in parent Server via callback.
	if st.cb.OnKeyRotated != nil {
		st.cb.OnKeyRotated(nodeID, oldPubKeyB64, newPubKeyB64)
	}

	// WAL the rotation. A normal rotate_key keeps the badge (the same
	// identity continues to hold the address), so clearBadge is false.
	if st.cb.RecordWAL != nil {
		st.cb.RecordWAL(nodeID, newPubKeyB64, rotatedAt.UTC().Format(time.RFC3339), false)
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}

	addr := protocol.Addr{Network: 0, Node: nodeID}
	slog.Debug("rotated key", "node_id", nodeID, "addr", addr)
	if st.cb.Audit != nil {
		st.cb.Audit("key.rotated", "node_id", nodeID)
	}
	if st.cb.IncKeyRotations != nil {
		st.cb.IncKeyRotations()
	}
	if st.cb.Bus != nil {
		st.cb.Bus.Publish(events.Event{
			Source:  "identity",
			Type:    "key.rotated",
			Payload: map[string]any{"node_id": nodeID},
		})
	}

	return map[string]interface{}{
		"type":       "rotate_key_ok",
		"node_id":    nodeID,
		"address":    addr.String(),
		"public_key": newPubKeyB64,
	}, nil
}

// HandleSetKeyExpiry implements the "set_key_expiry" protocol command.
func (st *Store) HandleSetKeyExpiry(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	expiresAtStr, _ := msg["expires_at"].(string)
	var expiresAt time.Time
	clearExpiry := expiresAtStr == "" || expiresAtStr == "never"
	if !clearExpiry {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at: %w", err)
		}
		now := st.nodes.Now()
		if expiresAt.Before(now) {
			return nil, fmt.Errorf("expires_at must be in the future")
		}
		if expiresAt.After(now.Add(10 * 365 * 24 * time.Hour)) {
			return nil, fmt.Errorf("invalid expires_at: cannot exceed 10 years")
		}
	}

	// Phase 1 — snapshot pubkey + adminToken for verification.
	currentPubKey, ok := st.nodes.LookupNodeKey(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}
	adminToken := st.nodes.AdminToken()

	// Phase 2 — verify signature outside the lock.
	sigErr := st.nodes.VerifyHeartbeatSignature(currentPubKey, adminToken, msg, fmt.Sprintf("set_key_expiry:%d", nodeID))
	if sigErr != nil {
		if err := st.nodes.CheckAdminToken(msg); err != nil {
			return nil, sigErr
		}
	}

	// Enterprise gate.
	if !st.nodes.NodeIsEnterprise(nodeID) {
		return nil, fmt.Errorf("enterprise feature: key expiry requires enterprise network membership")
	}

	// Phase 3 — commit.
	oldExpiry, ok := st.nodes.UpdateNodeKeyExpiry(nodeID, expiresAt)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}

	if clearExpiry {
		slog.Debug("cleared key expiry", "node_id", nodeID)
		if st.cb.Audit != nil {
			if !oldExpiry.IsZero() {
				st.cb.Audit("key.expiry_cleared", "node_id", nodeID, "old_expires_at", oldExpiry.Format(time.RFC3339))
			} else {
				st.cb.Audit("key.expiry_cleared", "node_id", nodeID)
			}
		}
		return map[string]interface{}{
			"type":    "set_key_expiry_ok",
			"node_id": nodeID,
		}, nil
	}

	slog.Debug("set key expiry", "node_id", nodeID, "expires_at", expiresAt)
	if st.cb.Audit != nil {
		if !oldExpiry.IsZero() {
			st.cb.Audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339), "old_expires_at", oldExpiry.Format(time.RFC3339))
		} else {
			st.cb.Audit("key.expiry_set", "node_id", nodeID, "expires_at", expiresAt.Format(time.RFC3339))
		}
	}

	return map[string]interface{}{
		"type":       "set_key_expiry_ok",
		"node_id":    nodeID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}, nil
}

// HandleGetKeyInfo implements the "get_key_info" protocol command.
func (st *Store) HandleGetKeyInfo(msg map[string]interface{}) (map[string]interface{}, error) {
	nodeID := jsonUint32(msg, "node_id")

	_, keyMeta, _, _, _, ok := st.nodes.LookupNodeFull(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d: %w", nodeID, protocol.ErrNodeNotFound)
	}

	resp := map[string]interface{}{
		"type":         "get_key_info_ok",
		"node_id":      nodeID,
		"created_at":   keyMeta.CreatedAt.Format(time.RFC3339),
		"rotate_count": keyMeta.RotateCount,
	}
	if !keyMeta.RotatedAt.IsZero() {
		resp["rotated_at"] = keyMeta.RotatedAt.Format(time.RFC3339)
	}
	if !keyMeta.ExpiresAt.IsZero() {
		resp["expires_at"] = keyMeta.ExpiresAt.Format(time.RFC3339)
	}

	keyStart := keyMeta.CreatedAt
	if !keyMeta.RotatedAt.IsZero() {
		keyStart = keyMeta.RotatedAt
	}
	if !keyStart.IsZero() {
		resp["key_age_days"] = int(time.Since(keyStart).Hours() / 24)
	}

	return resp, nil
}

// HandleGetIdentity implements the "get_identity" protocol command.
func (st *Store) HandleGetIdentity(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")

	_, _, _, externalID, owner, ok := st.nodes.LookupNodeFull(nodeID)
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	return map[string]interface{}{
		"type":        "get_identity_ok",
		"node_id":     nodeID,
		"external_id": externalID,
		"owner":       owner,
	}, nil
}

// HandleSetIdentityWebhook implements the "set_identity_webhook" protocol command.
// URL validation (SSRF prevention) must be performed by the caller before
// invoking this method.
func (st *Store) HandleSetIdentityWebhook(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	url, _ := msg["url"].(string)
	st.SetWebhookURL(url)
	status := "disabled"
	if url != "" {
		status = "enabled"
	}
	return map[string]interface{}{
		"type":   "set_identity_webhook_ok",
		"status": status,
	}, nil
}

// HandleSetExternalID implements the "set_external_id" protocol command.
func (st *Store) HandleSetExternalID(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	nodeID := jsonUint32(msg, "node_id")
	externalID, _ := msg["external_id"].(string)

	oldID, ok := st.nodes.UpdateNodeExternalID(nodeID, externalID)
	if !ok {
		return nil, fmt.Errorf("node not found")
	}

	if st.cb.Save != nil {
		st.cb.Save()
	}
	if st.cb.Audit != nil {
		st.cb.Audit("identity.external_id_set", "node_id", nodeID, "old_external_id", oldID, "new_external_id", externalID)
	}

	return map[string]interface{}{
		"type":        "set_external_id_ok",
		"node_id":     nodeID,
		"external_id": externalID,
	}, nil
}

// HandleSetIDPConfig implements the "set_idp_config" protocol command.
// URL validation (SSRF prevention) must be performed by the caller before
// invoking this method.
func (st *Store) HandleSetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	idpType, _ := msg["idp_type"].(string)
	url, _ := msg["url"].(string)

	if idpType == "" || url == "" {
		st.ClearIDPConfig()
		return map[string]interface{}{
			"type":   "set_idp_config_ok",
			"status": "disabled",
		}, nil
	}

	cfg := &BlueprintIdentityProvider{
		Type: idpType,
		URL:  url,
	}
	if v, ok := msg["issuer"].(string); ok {
		cfg.Issuer = v
	}
	if v, ok := msg["client_id"].(string); ok {
		cfg.ClientID = v
	}
	if v, ok := msg["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := msg["domain"].(string); ok {
		cfg.Domain = v
	}

	st.SetIDPConfig(cfg)

	if st.cb.Audit != nil {
		st.cb.Audit("idp.configured", "type", idpType, "url", url)
	}
	return map[string]interface{}{
		"type":     "set_idp_config_ok",
		"status":   "enabled",
		"idp_type": idpType,
	}, nil
}

// HandleGetIDPConfig implements the "get_idp_config" protocol command.
func (st *Store) HandleGetIDPConfig(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}
	cfg := st.GetIDPConfig()
	resp := map[string]interface{}{
		"type":       "get_idp_config_ok",
		"configured": cfg != nil,
	}
	if cfg != nil {
		resp["idp_type"] = cfg.Type
		resp["url"] = cfg.URL
		if cfg.Issuer != "" {
			resp["issuer"] = cfg.Issuer
		}
		if cfg.ClientID != "" {
			resp["client_id"] = cfg.ClientID
		}
		if cfg.TenantID != "" {
			resp["tenant_id"] = cfg.TenantID
		}
		if cfg.Domain != "" {
			resp["domain"] = cfg.Domain
		}
	}
	return resp, nil
}

// HandleGetProvisionStatus implements the "get_provision_status" protocol command.
// The networkSummary callback produces the per-network list so the Store
// does not need to access s.networks directly.
func (st *Store) HandleGetProvisionStatus(
	msg map[string]interface{},
	networkSummary func() []map[string]interface{},
	webhookEnabled bool,
	auditExportFormat string,
) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	networks := networkSummary()
	if networks == nil {
		networks = []map[string]interface{}{}
	}

	resp := map[string]interface{}{
		"type":     "get_provision_status_ok",
		"networks": networks,
	}

	cfg := st.GetIDPConfig()
	if cfg != nil {
		resp["idp_type"] = cfg.Type
	}
	if auditExportFormat != "" {
		resp["audit_export"] = auditExportFormat
	}
	if webhookEnabled {
		resp["webhook_enabled"] = true
	}
	return resp, nil
}

// HandleValidateToken implements the "validate_token" protocol command.
func (st *Store) HandleValidateToken(msg map[string]interface{}) (map[string]interface{}, error) {
	if err := st.nodes.CheckAdminToken(msg); err != nil {
		return nil, err
	}

	token, _ := msg["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	idp := st.GetIDPConfig()
	if idp == nil {
		return nil, fmt.Errorf("no identity provider configured")
	}

	header, claims, signingInput, err := DecodeJWT(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if err := ValidateJWTClaims(claims, idp.Issuer, idp.ClientID); err != nil {
		return map[string]interface{}{
			"type":     "validate_token_ok",
			"verified": false,
			"error":    err.Error(),
		}, nil
	}

	parts := strings.SplitN(token, ".", 3)

	switch header.Alg {
	case "HS256":
		key, err := st.jwksCache.GetKeyWithPinning(idp.URL, header.Kid, st.pinnedCertFingerprint)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		if key.Alg != "" && key.Alg != "HS256" {
			return nil, fmt.Errorf("algorithm mismatch: JWT header says HS256, JWKS key says %s", key.Alg)
		}
		if key.Kty != "" && key.Kty != "oct" {
			return nil, fmt.Errorf("key type mismatch: HS256 requires oct key, got %s", key.Kty)
		}
		secret, err := base64.RawURLEncoding.DecodeString(key.K)
		if err != nil {
			return nil, fmt.Errorf("decode HMAC key: %w", err)
		}
		if err := VerifyJWTSignatureHS256(signingInput, parts[2], secret); err != nil {
			return map[string]interface{}{
				"type":     "validate_token_ok",
				"verified": false,
				"error":    err.Error(),
			}, nil
		}

	case "RS256":
		key, err := st.jwksCache.GetKeyWithPinning(idp.URL, header.Kid, st.pinnedCertFingerprint)
		if err != nil {
			return nil, fmt.Errorf("JWKS: %w", err)
		}
		if key.Alg != "" && key.Alg != "RS256" {
			return nil, fmt.Errorf("algorithm mismatch: JWT header says RS256, JWKS key says %s", key.Alg)
		}
		if key.Kty != "" && key.Kty != "RSA" {
			return nil, fmt.Errorf("key type mismatch: RS256 requires RSA key, got %s", key.Kty)
		}
		if err := verifyJWTSignatureRS256(signingInput, parts[2], key); err != nil {
			return map[string]interface{}{
				"type":     "validate_token_ok",
				"verified": false,
				"error":    err.Error(),
			}, nil
		}

	default:
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", header.Alg)
	}

	if st.cb.IncIDPVerifications != nil {
		st.cb.IncIDPVerifications()
	}
	return map[string]interface{}{
		"type":     "validate_token_ok",
		"verified": true,
		"subject":  claims.Subject,
		"issuer":   claims.Issuer,
	}, nil
}

// ---------------------------------------------------------------------------
// JWT / JWKS internals (moved from identity.go)
// ---------------------------------------------------------------------------

type identityVerifyRequest struct {
	Token string `json:"token"`
}

type identityVerifyResponse struct {
	Verified   bool   `json:"verified"`
	ExternalID string `json:"external_id"`
	Error      string `json:"error,omitempty"`
}

type JwtClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  JwtAud `json:"aud"`
	Expiry    int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
}

type JwtAud []string

func (a *JwtAud) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err == nil {
		*a = ss
		return nil
	}
	return fmt.Errorf("aud must be string or []string")
}

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func DecodeJWT(token string) (*JwtHeader, *JwtClaims, string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT header: %w", err)
	}
	var header JwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT header: %w", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims JwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, nil, "", fmt.Errorf("parse JWT claims: %w", err)
	}

	return &header, &claims, parts[0] + "." + parts[1], nil
}

const jwtClockSkew = 60

func ValidateJWTClaims(claims *JwtClaims, expectedIssuer, expectedAudience string) error {
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return fmt.Errorf("issuer mismatch: got %q, want %q", claims.Issuer, expectedIssuer)
	}

	if expectedAudience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience mismatch: got %v, want %q", []string(claims.Audience), expectedAudience)
		}
	}

	now := time.Now().Unix()
	if claims.Expiry > 0 && claims.Expiry < now-jwtClockSkew {
		return fmt.Errorf("token expired at %d (now %d)", claims.Expiry, now)
	}
	if claims.NotBefore > 0 && claims.NotBefore > now+jwtClockSkew {
		return fmt.Errorf("token not yet valid (nbf %d, now %d)", claims.NotBefore, now)
	}

	return nil
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

type JwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	K   string `json:"k,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKSCache holds a cached set of JWKS keys for a single issuer URL.
// Fields are exported so that white-box tests in package server can
// construct a cache with pre-populated state.
type JWKSCache struct {
	mu        sync.RWMutex
	Keys      []JwksKey
	URL       string
	FetchedAt time.Time
	TTL       time.Duration
}

// jwksCache is an alias kept for internal use within this package.
type jwksCache = JWKSCache

// JwksCacheTTL is the default TTL for cached JWKS keys.
const JwksCacheTTL = 5 * time.Minute

// jwksCacheTTL is the internal constant (same value, kept for existing code).
const jwksCacheTTL = JwksCacheTTL

// NewJWKSCache returns a new JWKSCache with the default TTL.
func NewJWKSCache() *JWKSCache {
	return &JWKSCache{TTL: JwksCacheTTL}
}

func newJWKSCache() *JWKSCache {
	return NewJWKSCache()
}

// jwksPinnedHTTPClient returns an HTTP client for JWKS fetch that enforces
// TLS certificate pinning when a pinnedFingerprint is provided. The
// fingerprint is a lowercase hex-encoded SHA-256 hash of the DER-encoded
// certificate. When no fingerprint is set, the standard jwksHTTPClient
// is returned (PILOT-241).
func jwksPinnedHTTPClient(pinnedFingerprint string) *http.Client {
	if pinnedFingerprint == "" {
		return jwksHTTPClient
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no peer certificate to pin")
					}
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return fmt.Errorf("parse peer certificate: %w", err)
					}
					h := sha256.Sum256(cert.Raw)
					got := hex.EncodeToString(h[:])
					if !strings.EqualFold(got, pinnedFingerprint) {
						return fmt.Errorf("certificate fingerprint mismatch: got %s, want %s", got, pinnedFingerprint)
					}
					return nil
				},
				// InsecureSkipVerify is true because VerifyPeerCertificate does
				// the actual cert verification via fingerprint check. The standard
				// chain verification is bypassed to allow self-signed or
				// non-CA-signed certs that match the pinned fingerprint.
				InsecureSkipVerify: true,
			},
		},
	}
}

// GetKey returns the JWKS key for the given URL and kid, fetching if stale.
// Pinning is not applied; use GetKeyWithPinning for pinned TLS verification.
func (c *JWKSCache) GetKey(jwksURL, kid string) (*JwksKey, error) {
	return c.GetKeyWithPinning(jwksURL, kid, "")
}

// GetKeyWithPinning returns the JWKS key for the given URL and kid, fetching
// if stale. When pinnedFingerprint is non-empty, the TLS connection is
// verified against the certificate fingerprint (SHA-256 of DER) so that a
// MITM serving a different certificate is rejected (PILOT-241).
func (c *JWKSCache) GetKeyWithPinning(jwksURL, kid, pinnedFingerprint string) (*JwksKey, error) {
	c.mu.RLock()
	if c.URL == jwksURL && time.Since(c.FetchedAt) < c.TTL && len(c.Keys) > 0 {
		if kid == "" {
			if len(c.Keys) == 1 {
				key := c.Keys[0]
				c.mu.RUnlock()
				return &key, nil
			}
			c.mu.RUnlock()
			return nil, fmt.Errorf("JWT missing required 'kid' header; JWKS has %d keys", len(c.Keys))
		}
		for i := range c.Keys {
			if c.Keys[i].Kid == kid {
				key := c.Keys[i]
				c.mu.RUnlock()
				return &key, nil
			}
		}
		c.mu.RUnlock()
		return nil, fmt.Errorf("JWKS key %q not found (cached)", kid)
	}
	c.mu.RUnlock()

	keys, err := FetchJWKSKeysWithPinning(jwksURL, pinnedFingerprint)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.Keys = keys
	c.URL = jwksURL
	c.FetchedAt = time.Now()
	c.mu.Unlock()

	if kid == "" {
		if len(keys) == 1 {
			return &keys[0], nil
		}
		return nil, fmt.Errorf("JWT missing required 'kid' header; JWKS has %d keys", len(keys))
	}
	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("JWKS key %q not found", kid)
}

// getKey is the unexported accessor kept for backward compatibility within the package.
func (c *JWKSCache) getKey(jwksURL, kid string) (*JwksKey, error) {
	return c.GetKey(jwksURL, kid)
}

// FetchJWKSKeys fetches the list of JWKS keys from the given URL.
func FetchJWKSKeys(jwksURL string) ([]JwksKey, error) {
	return fetchJWKSKeys(jwksURL)
}

func fetchJWKSKeys(jwksURL string) ([]JwksKey, error) {
	return fetchJWKSKeysWithClient(jwksURL, jwksHTTPClient)
}

// FetchJWKSKeysWithPinning fetches JWKS keys with TLS certificate pinning.
// The pinnedFingerprint is a hex-encoded SHA-256 of the DER certificate.
func FetchJWKSKeysWithPinning(jwksURL, pinnedFingerprint string) ([]JwksKey, error) {
	client := jwksPinnedHTTPClient(pinnedFingerprint)
	return fetchJWKSKeysWithClient(jwksURL, client)
}

func fetchJWKSKeysWithClient(jwksURL string, client *http.Client) ([]JwksKey, error) {
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	var jwks struct {
		Keys []JwksKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return jwks.Keys, nil
}

func VerifyJWTSignatureHS256(signingInput string, signatureB64 string, secret []byte) error {
	expectedSig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	computed := mac.Sum(nil)
	if !hmac.Equal(computed, expectedSig) {
		return fmt.Errorf("invalid HMAC signature")
	}
	return nil
}

// VerifyJWTSignatureRS256 verifies an RS256 JWT signature using the given JwksKey.
func VerifyJWTSignatureRS256(signingInput, signatureB64 string, key *JwksKey) error {
	return verifyJWTSignatureRS256(signingInput, signatureB64, key)
}

func verifyJWTSignatureRS256(signingInput, signatureB64 string, key *JwksKey) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("decode RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	sig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, gocrypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("invalid RSA signature: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func jsonUint32(msg map[string]interface{}, key string) uint32 {
	v, ok := msg[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return uint32(n)
	case uint32:
		return n
	case int:
		return uint32(n)
	}
	return 0
}

func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// HashOwner returns a truncated SHA-256 hash of the owner for safe logging.
func HashOwner(owner string) string {
	if owner == "" {
		return ""
	}
	h := sha256.Sum256([]byte(owner))
	return fmt.Sprintf("sha256:%x", h[:4])
}
