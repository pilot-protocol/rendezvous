// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit manages the registry audit log ring buffer and optional
// external export (Splunk HEC, syslog/CEF, plain JSON).
//
// Fan-out from the server's audit() helper to the ring buffer and exporter
// is async: server.audit() publishes an "audit.entry" event on the shared
// events.Bus; Store.Subscribe starts a background goroutine that consumes
// those events and writes them here. This removes the direct coupling
// between the server's hot request path and the audit I/O.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/rendezvous/events"
	"github.com/pilot-protocol/common/registry/wire"
)

// Entry records a single audit event. The JSON tags match the on-wire format
// used by handleGetAuditLog and the snapshot serialiser.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	NetworkID uint16 `json:"network_id,omitempty"`
	NodeID    uint32 `json:"node_id,omitempty"`
	Details   string `json:"details,omitempty"`

	// Hash-chain fields for tamper-evidence.
	// PrevHash is the SHA-256 hex digest of the previous entry
	// (empty for the genesis entry). Hash is the SHA-256 hex
	// digest of this entry encompassing PrevHash, Timestamp,
	// Action, NetworkID, NodeID, and Details.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

const maxEntries = 1000

// Store holds the in-memory audit ring buffer and the optional external
// export adapter. All exported methods are safe for concurrent use.
type Store struct {
	mu  sync.Mutex
	log []Entry

	// lastHash caches the hash of the most recent entry to avoid
	// re-reading the ring buffer on every Append. Empty for a
	// fresh or empty store.
	lastHash string

	// Export adapter — nil when export is disabled.
	exporter *AuditExporter
	cfg      *wire.BlueprintAuditExport

	// unsub stops the bus subscriber goroutine started by Subscribe.
	unsub func()
}

// NewStore creates an empty Store with no exporter configured.
func NewStore() *Store {
	return &Store{}
}

// Subscribe starts a background goroutine that reads "audit.entry" events
// from the bus and forwards each one to the configured exporter. Ring-buffer
// writes are synchronous (via Append); this goroutine handles only async
// exporter fan-out. Call it once after constructing the Store.
func (st *Store) Subscribe(bus events.Bus) {
	ch, unsub := bus.Subscribe("audit.entry")
	st.unsub = unsub
	go func() {
		for evt := range ch {
			st.handleExporterFanout(evt)
		}
	}()
}

// Close stops the bus subscriber goroutine and drains/closes the exporter.
func (st *Store) Close() {
	if st.unsub != nil {
		st.unsub()
		st.unsub = nil
	}
	st.mu.Lock()
	exp := st.exporter
	st.exporter = nil
	st.mu.Unlock()
	if exp != nil {
		exp.Close()
	}
}

// handleExporterFanout forwards bus events to the exporter.
// The ring buffer is written synchronously before the event is published,
// so this function only needs to fan out to the external exporter.
func (st *Store) handleExporterFanout(evt events.Event) {
	st.mu.Lock()
	exp := st.exporter
	st.mu.Unlock()
	if exp == nil {
		return
	}
	p := evt.Payload

	action, _ := p["action"].(string)
	netID, _ := p["network_id"].(uint16)
	nodeID, _ := p["node_id"].(uint32)
	details, _ := p["details"].(string)
	ts, _ := p["timestamp"].(string)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	e := Entry{
		Timestamp: ts,
		Action:    action,
		NetworkID: netID,
		NodeID:    nodeID,
		Details:   details,
	}
	exp.Export(&e)
}

// Append directly inserts an entry into the ring buffer and forwards it to
// the exporter (if configured). It is used by the snapshot restore path
// which bypasses the bus (no need to publish historical entries).
//
// Each entry is linked to its predecessor via a SHA-256 hash chain,
// providing tamper-evident integrity. The genesis entry has an empty
// PrevHash.
func (st *Store) Append(e Entry) {
	e.PrevHash = st.lastHash
	e.Hash = hashEntry(e.PrevHash, e.Timestamp, e.Action, e.NetworkID, e.NodeID, e.Details)

	st.mu.Lock()
	if len(st.log) >= maxEntries {
		st.log = st.log[1:]
	}
	st.log = append(st.log, e)
	st.lastHash = e.Hash
	exp := st.exporter
	st.mu.Unlock()

	if exp != nil {
		exp.Export(&e)
	}
}

// Snapshot returns a copy of the current audit log (oldest first).
func (st *Store) Snapshot() []Entry {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.log) == 0 {
		return nil
	}
	out := make([]Entry, len(st.log))
	copy(out, st.log)
	return out
}

// RestoreLog replaces the ring buffer with the provided slice (used during
// snapshot restore on startup). If the entries already carry a valid hash
// chain it is preserved; otherwise the chain is rebuilt from scratch.
func (st *Store) RestoreLog(entries []Entry) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.log = entries
	st.rebuildHashChain()
}

// SetExporter replaces the current exporter with a new one built from cfg.
// The old exporter (if any) is drained and closed. Pass nil cfg to disable.
func (st *Store) SetExporter(cfg *wire.BlueprintAuditExport) {
	st.mu.Lock()
	old := st.exporter
	if cfg == nil {
		st.exporter = nil
		st.cfg = nil
	} else {
		st.exporter = newAuditExporter(cfg)
		st.cfg = cfg
	}
	st.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

// ExporterConfig returns the active export configuration (nil = disabled).
func (st *Store) ExporterConfig() *wire.BlueprintAuditExport {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.cfg
}

// ExporterStats returns (exported, dropped) counters from the active exporter.
func (st *Store) ExporterStats() (exported, dropped uint64) {
	st.mu.Lock()
	exp := st.exporter
	st.mu.Unlock()
	if exp == nil {
		return 0, 0
	}
	return exp.Stats()
}

// HandleGetAuditExport builds the response map for a "get_audit_export"
// protocol request. adminCheck must be called by the caller before invoking
// this method (the server wraps this in handleGetAuditExport which first
// calls requireAdminToken).
func (st *Store) HandleGetAuditExport(_ map[string]interface{}) (map[string]interface{}, error) {
	st.mu.Lock()
	cfg := st.cfg
	exp := st.exporter
	st.mu.Unlock()

	resp := map[string]interface{}{
		"type":    "get_audit_export_ok",
		"enabled": cfg != nil,
	}
	if cfg != nil {
		resp["format"] = cfg.Format
		resp["endpoint"] = cfg.Endpoint
		if exp != nil {
			exported, dropped := exp.Stats()
			resp["exported"] = exported
			resp["dropped"] = dropped
		}
	}
	return resp, nil
}

// FilteredEntries returns audit entries newest-first, filtered by netID (0 =
// all) and limited to at most limit entries.
func (st *Store) FilteredEntries(filterNetID uint16, limit int) []map[string]interface{} {
	st.mu.Lock()
	all := make([]Entry, len(st.log))
	copy(all, st.log)
	st.mu.Unlock()

	var out []map[string]interface{}
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		e := all[i]
		if filterNetID != 0 && e.NetworkID != filterNetID {
			continue
		}
		m := map[string]interface{}{
			"timestamp": e.Timestamp,
			"action":    e.Action,
		}
		if e.NetworkID != 0 {
			m["network_id"] = e.NetworkID
		}
		if e.NodeID != 0 {
			m["node_id"] = e.NodeID
		}
		if e.Details != "" {
			m["details"] = e.Details
		}
		out = append(out, m)
	}
	if out == nil {
		out = []map[string]interface{}{}
	}
	return out
}

// hashEntry computes the SHA-256 hex digest of a single audit entry
// linked to the previous entry via prevHash. The serialisation order is
// deliberately not JSON — we use binary.Write for the fixed-width fields
// to avoid any ambiguity around field ordering, whitespace, or encoding
// differences that could break the chain across versions.
func hashEntry(prevHash, timestamp, action string, networkID uint16, nodeID uint32, details string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(timestamp))
	h.Write([]byte(action))
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[:2], networkID)
	h.Write(buf[:2])
	binary.BigEndian.PutUint32(buf[:4], nodeID)
	h.Write(buf[:4])
	h.Write([]byte(details))
	return hex.EncodeToString(h.Sum(nil))
}

// rebuildHashChain recomputes the hash chain from the first entry to the
// last. Caller must hold st.mu. Idempotent: if the chain is already valid
// we leave it untouched; if any entry carries zero hashes or a broken link
// the chain is rebuilt.
func (st *Store) rebuildHashChain() {
	if len(st.log) == 0 {
		st.lastHash = ""
		return
	}
	for i := range st.log {
		e := &st.log[i]
		expected := hashEntry(e.PrevHash, e.Timestamp, e.Action, e.NetworkID, e.NodeID, e.Details)
		if i == 0 {
			// Genesis: accept the existing hash if it exists;
			// otherwise compute and fill.
			if e.Hash == "" {
				e.PrevHash = ""
				e.Hash = expected
			}
		} else {
			prev := st.log[i-1]
			if e.PrevHash != prev.Hash || e.Hash != expected {
				e.PrevHash = prev.Hash
				e.Hash = expected
			}
		}
	}
	st.lastHash = st.log[len(st.log)-1].Hash
}

// VerifyIntegrity walks the hash chain from the oldest entry to the
// newest. It returns the index of the first entry whose hash does not
// match, or -1 when the chain is fully intact.
func (st *Store) VerifyIntegrity() int {
	st.mu.Lock()
	defer st.mu.Unlock()

	var prevHash string
	for i := range st.log {
		e := &st.log[i]
		if e.PrevHash != prevHash {
			return i
		}
		expected := hashEntry(e.PrevHash, e.Timestamp, e.Action, e.NetworkID, e.NodeID, e.Details)
		if e.Hash != expected {
			return i
		}
		prevHash = e.Hash
	}
	return -1
}

func BuildEntry(action string, netID uint16, nodeID uint32, attrs ...any) Entry {
	for i := 0; i+1 < len(attrs); i += 2 {
		k, ok := attrs[i].(string)
		if !ok {
			continue
		}
		if k == "node_id" && nodeID == 0 {
			switch v := attrs[i+1].(type) {
			case uint32:
				nodeID = v
			case int:
				nodeID = uint32(v)
			case float64:
				nodeID = uint32(v)
			}
		}
		if k == "network_id" && netID == 0 {
			switch v := attrs[i+1].(type) {
			case uint16:
				netID = v
			case int:
				netID = uint16(v)
			case float64:
				netID = uint16(v)
			}
		}
	}

	var details string
	for i := 0; i+1 < len(attrs); i += 2 {
		if k, ok := attrs[i].(string); ok && k != "node_id" && k != "network_id" {
			if details != "" {
				details += ", "
			}
			val := attrs[i+1]
			if redactKey(k) {
				val = "<redacted>"
			}
			details += fmt.Sprintf("%s=%v", k, val)
		}
	}

	return Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Action:    action,
		NetworkID: netID,
		NodeID:    nodeID,
		Details:   details,
	}
}

// redactKey returns true when an attribute key is known to carry
// secret material that must not be persisted in the audit log.
//
// The audit log was already a security-relevant surface (anyone with
// log read can replay history); leaving tokens and passwords in the
// Details field made it ALSO a credential-disclosure surface. The
// redaction list is conservative — only fields whose name strongly
// implies "secret" are redacted; legitimate non-secret keys with
// similar names should be renamed in the call site rather than added
// to an exclude list.
func redactKey(k string) bool {
	switch strings.ToLower(k) {
	case "token", "admin_token", "password", "passwd", "secret",
		"api_key", "apikey", "private_key", "signature", "challenge",
		"auth", "authorization", "bearer", "credential", "credentials":
		return true
	}
	// Suffix heuristic: anything ending in "_token", "_secret",
	// "_password", "_key" is treated as sensitive.
	low := strings.ToLower(k)
	for _, suf := range []string{"_token", "_secret", "_password", "_key"} {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}
