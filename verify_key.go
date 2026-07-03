// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// verdictKeyKid is the key ID published on GET /api/v1/verify/keys and echoed
// as verdict_kid in every verification response. Bump when the verdict key
// format or rotation policy changes.
const verdictKeyKid = "vfy-v1"

// verdictKeyFileName is the on-disk file holding the verdict signing key.
// It lives next to the registry snapshot (same directory as registry.json).
const verdictKeyFileName = "verdict-key.json"

// verdictKeyFile is the JSON shape persisted at verdictKeyFileName. The
// private key is the full 64-byte Ed25519 private key (seed + public half),
// base64 std encoding.
type verdictKeyFile struct {
	Kid        string `json:"kid"`
	PrivateKey string `json:"private_key"`
}

// verdictKeyPath returns the on-disk path for the verdict key, or "" when
// the server runs without a persistence path.
func (s *Server) verdictKeyPath() string {
	if s.storePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.storePath), verdictKeyFileName)
}

// initVerdictKey lazily loads or generates the verdict signing keypair.
// Without a persistence path the key is ephemeral (in-memory only);
// otherwise it is loaded from — or generated and persisted to —
// verdict-key.json next to the registry snapshot. The private key is
// NEVER logged; error values carry paths only, no key material.
func (s *Server) initVerdictKey() {
	s.verdictKeyOnce.Do(func() {
		kid, priv, err := loadOrCreateVerdictKey(s.verdictKeyPath())
		if err != nil {
			// A persistence failure must not take the verification
			// endpoint down: fall back to an ephemeral key and surface
			// the error. Verdicts stay verifiable via /api/v1/verify/keys,
			// which always serves the live public key.
			slog.Warn("verdict key persistence failed; using ephemeral key", "err", err)
			_, ephemeral, genErr := ed25519.GenerateKey(rand.Reader)
			if genErr != nil {
				slog.Error("verdict key generation failed; verdict signing disabled", "err", genErr)
				return
			}
			kid, priv = verdictKeyKid, ephemeral
		}
		s.verdictKid = kid
		s.verdictPriv = priv
	})
}

// VerdictKid returns the key ID of the verdict signing key.
func (s *Server) VerdictKid() string {
	s.initVerdictKey()
	return s.verdictKid
}

// VerdictPublicKey returns the public half of the verdict signing key, or
// nil when verdict signing is unavailable.
func (s *Server) VerdictPublicKey() ed25519.PublicKey {
	s.initVerdictKey()
	if s.verdictPriv == nil {
		return nil
	}
	return s.verdictPriv.Public().(ed25519.PublicKey)
}

// loadOrCreateVerdictKey loads the verdict keypair from path, generating and
// persisting a fresh one (mode 0600, atomic tmp+rename) when the file does
// not exist yet. path == "" generates an in-memory ephemeral key.
func loadOrCreateVerdictKey(path string) (kid string, priv ed25519.PrivateKey, err error) {
	if path == "" {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", nil, fmt.Errorf("verdict key generate: %w", err)
		}
		return verdictKeyKid, priv, nil
	}

	data, readErr := os.ReadFile(path)
	if readErr == nil {
		var f verdictKeyFile
		if err := json.Unmarshal(data, &f); err != nil {
			return "", nil, fmt.Errorf("verdict key %s: %w", path, err)
		}
		raw, err := base64.StdEncoding.DecodeString(f.PrivateKey)
		if err != nil {
			return "", nil, fmt.Errorf("verdict key %s: private_key not base64: %w", path, err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return "", nil, fmt.Errorf("verdict key %s: bad private key length %d", path, len(raw))
		}
		if f.Kid == "" {
			f.Kid = verdictKeyKid
		}
		return f.Kid, ed25519.PrivateKey(raw), nil
	}
	if !os.IsNotExist(readErr) {
		return "", nil, fmt.Errorf("verdict key %s: %w", path, readErr)
	}

	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("verdict key generate: %w", err)
	}
	blob, err := json.Marshal(verdictKeyFile{
		Kid:        verdictKeyKid,
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	})
	if err != nil {
		return "", nil, fmt.Errorf("verdict key marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return "", nil, fmt.Errorf("verdict key write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", nil, fmt.Errorf("verdict key rename %s: %w", path, err)
	}
	return verdictKeyKid, priv, nil
}
