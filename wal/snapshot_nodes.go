// SPDX-License-Identifier: AGPL-3.0-or-later

package wal

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// SnapshotNodes is the node map field of Snapshot. It's a named type so it can
// implement a hand-written MarshalJSON: encoding/json's reflection-based map
// encoder is the single most expensive part of a fleet-scale snapshot
// (~200k entries), and it allocates heavily (driving GC on the registry box).
//
// The output is byte-identical to encoding/json (differential-tested): same
// key ordering (ascending), same field order/omitempty per node, same string
// escaping (HTML escaping disabled, matching the snapshot encoder). load()
// re-encodes to verify the checksum, so byte-equality is required.
type SnapshotNodes map[string]*SnapshotNode

// MarshalJSON is reflection-free and, on the hot path, allocation-free beyond
// the single result buffer.
func (m SnapshotNodes) MarshalJSON() ([]byte, error) {
	return m.appendTo(nil), nil
}

// appendTo appends the encoding/json-compatible object encoding of m to dst.
// Serial by design: the encoder is memory-bandwidth-bound, so chunking across
// goroutines measured no faster while allocating ~18x more, and the reused
// dst keeps this allocation-free beyond dst's own growth.
func (m SnapshotNodes) appendTo(dst []byte) []byte {
	if m == nil {
		return append(dst, "null"...)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // encoding/json emits map keys in ascending order
	dst = append(dst, '{')
	for i, k := range keys {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, k)
		dst = append(dst, ':')
		dst = appendSnapshotNode(dst, m[k])
	}
	return append(dst, '}')
}

// appendJSONString appends s as a JSON string. Fast path for printable ASCII
// with no quote/backslash (base64 keys, addresses, hostnames, RFC3339,
// "min:max"); anything else (control chars, non-ASCII, invalid UTF-8) falls
// back to encoding/json with SetEscapeHTML(false) so bytes match exactly.
func appendJSONString(dst []byte, s string) []byte {
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' || c >= 0x80 {
			safe = false
			break
		}
	}
	if safe {
		dst = append(dst, '"')
		dst = append(dst, s...)
		return append(dst, '"')
	}
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return append(dst, b...)
}

func appendU16Slice(dst []byte, s []uint16) []byte {
	if s == nil {
		return append(dst, "null"...)
	}
	dst = append(dst, '[')
	for i, v := range s {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendUint(dst, uint64(v), 10)
	}
	return append(dst, ']')
}

func appendStringSlice(dst []byte, s []string) []byte {
	if s == nil {
		return append(dst, "null"...)
	}
	dst = append(dst, '[')
	for i, v := range s {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, v)
	}
	return append(dst, ']')
}

// appendSnapshotNode mirrors SnapshotNode's struct-tag field order and
// omitempty rules exactly.
func appendSnapshotNode(dst []byte, n *SnapshotNode) []byte {
	if n == nil {
		return append(dst, "null"...)
	}
	dst = append(dst, '{')
	first := true
	key := func(name string) {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, '"')
		dst = append(dst, name...)
		dst = append(dst, '"', ':')
	}
	key("id")
	dst = strconv.AppendUint(dst, uint64(n.ID), 10)
	if n.Owner != "" {
		key("owner")
		dst = appendJSONString(dst, n.Owner)
	}
	key("public_key")
	dst = appendJSONString(dst, n.PublicKey)
	if n.RealAddr != "" {
		key("real_addr")
		dst = appendJSONString(dst, n.RealAddr)
	}
	key("networks")
	dst = appendU16Slice(dst, n.Networks)
	if n.Public {
		key("public")
		dst = append(dst, "true"...)
	}
	if n.LastSeen != "" {
		key("last_seen")
		dst = appendJSONString(dst, n.LastSeen)
	}
	if n.Hostname != "" {
		key("hostname")
		dst = appendJSONString(dst, n.Hostname)
	}
	if len(n.Tags) > 0 {
		key("tags")
		dst = appendStringSlice(dst, n.Tags)
	}
	if n.TaskExec {
		key("task_exec")
		dst = append(dst, "true"...)
	}
	if len(n.LANAddrs) > 0 {
		key("lan_addrs")
		dst = appendStringSlice(dst, n.LANAddrs)
	}
	if n.KeyCreated != "" {
		key("key_created")
		dst = appendJSONString(dst, n.KeyCreated)
	}
	if n.KeyRotated != "" {
		key("key_rotated")
		dst = appendJSONString(dst, n.KeyRotated)
	}
	if n.KeyRotCount != 0 {
		key("key_rot_count")
		dst = strconv.AppendInt(dst, int64(n.KeyRotCount), 10)
	}
	if n.KeyExpires != "" {
		key("key_expires")
		dst = appendJSONString(dst, n.KeyExpires)
	}
	if n.ExternalID != "" {
		key("external_id")
		dst = appendJSONString(dst, n.ExternalID)
	}
	if n.Version != "" {
		key("version")
		dst = appendJSONString(dst, n.Version)
	}
	if n.RelayOnly {
		key("relay_only")
		dst = append(dst, "true"...)
	}
	if n.Badge != "" {
		key("badge")
		dst = appendJSONString(dst, n.Badge)
	}
	if n.BadgeSig != "" {
		key("badge_sig")
		dst = appendJSONString(dst, n.BadgeSig)
	}
	if n.VerificationProvider != "" {
		key("verification_provider")
		dst = appendJSONString(dst, n.VerificationProvider)
	}
	if n.VerifiedAt != "" {
		key("verified_at")
		dst = appendJSONString(dst, n.VerifiedAt)
	}
	if n.RecoveryCommitment != "" {
		key("recovery_commitment")
		dst = appendJSONString(dst, n.RecoveryCommitment)
	}
	if n.RecoveryProvider != "" {
		key("recovery_provider")
		dst = appendJSONString(dst, n.RecoveryProvider)
	}
	if n.RecoveryConsumedNonce != "" {
		key("recovery_consumed_nonce")
		dst = appendJSONString(dst, n.RecoveryConsumedNonce)
	}
	if n.RecoveryConsumedExp != "" {
		key("recovery_consumed_exp")
		dst = appendJSONString(dst, n.RecoveryConsumedExp)
	}
	return append(dst, '}')
}
