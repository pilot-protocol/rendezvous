// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// AuditWAL persists audit entries to disk in JSON-lines format before they
// enter the export channel. On clean shutdown the WAL is truncated; on crash
// restart all entries are replayed for re-export.
type AuditWAL struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewAuditWAL opens or creates the WAL file at path. Returns nil when path
// is empty (no persistence configured).
func NewAuditWAL(path string) (*AuditWAL, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit WAL: %w", err)
	}
	return &AuditWAL{f: f, path: path}, nil
}

// Append writes an audit entry as a JSON line to the WAL and fsyncs.
func (w *AuditWAL) Append(entry *Entry) error {
	if w == nil {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit WAL: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	line := append(data, '\n')
	if _, err := w.f.Write(line); err != nil {
		return fmt.Errorf("write audit WAL: %w", err)
	}
	return w.f.Sync()
}

// Pending reads all entries from the WAL for replay, oldest first.
func (w *AuditWAL) Pending() ([]Entry, error) {
	if w == nil {
		return nil, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek audit WAL start: %w", err)
	}
	var entries []Entry
	dec := json.NewDecoder(w.f)
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return entries, fmt.Errorf("decode audit WAL entry: %w", err)
		}
		entries = append(entries, e)
	}
	if _, err := w.f.Seek(0, io.SeekEnd); err != nil {
		return entries, fmt.Errorf("seek audit WAL end: %w", err)
	}
	return entries, nil
}

// Truncate clears the WAL. Called after clean drain on shutdown.
func (w *AuditWAL) Truncate() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Truncate(0); err != nil {
		return fmt.Errorf("truncate audit WAL: %w", err)
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek audit WAL after truncate: %w", err)
	}
	return w.f.Sync()
}

// Close closes the underlying file.
func (w *AuditWAL) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
