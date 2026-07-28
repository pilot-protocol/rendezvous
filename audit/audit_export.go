// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// AuditExporter sends audit events to an external system in the configured
// format (Splunk HEC, syslog/CEF, or plain JSON). It runs asynchronously
// with a buffered channel, just like registryWebhook.
type AuditExporter struct {
	config    *wire.BlueprintAuditExport
	ch        chan *Entry
	client    *http.Client
	done      chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
	exported  atomic.Uint64
	dropped   atomic.Uint64
	wal       *AuditWAL
}

// NewAuditExporter creates and starts a new AuditExporter for the given config.
// It is exported so that the server package shim (audit_export.go) can
// delegate to it without the sub-package re-implementing the constructor.
func NewAuditExporter(cfg *wire.BlueprintAuditExport) *AuditExporter {
	return newAuditExporter(cfg, "")
}

// NewAuditExporterWithWAL creates and starts a new AuditExporter with an
// on-disk write-ahead log at walPath. Use empty walPath to disable the WAL.
func NewAuditExporterWithWAL(cfg *wire.BlueprintAuditExport, walPath string) *AuditExporter {
	return newAuditExporter(cfg, walPath)
}

func newAuditExporter(cfg *wire.BlueprintAuditExport, walPath string) *AuditExporter {
	w, err := NewAuditWAL(walPath)
	if err != nil {
		slog.Warn("audit exporter: failed to open WAL, continuing without persistence", "path", walPath, "error", err)
	}

	ae := &AuditExporter{
		config: cfg,
		ch:     make(chan *Entry, 1024),
		client: &http.Client{Timeout: 10 * time.Second},
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		wal:    w,
	}

	// Replay any WAL entries from a previous crash into the channel.
	// Non-blocking: if the channel fills, remaining entries are dropped
	// (they will be replayed again on next restart until exported).
	if w != nil {
		pending, err := w.Pending()
		if err != nil {
			slog.Error("audit exporter: WAL replay failed", "error", err)
		}
		for i := range pending {
			entry := pending[i] // capture
			select {
			case ae.ch <- &entry:
			default:
				slog.Warn("audit exporter: dropping replayed WAL entry (channel full)", "action", entry.Action)
			}
		}
		if len(pending) > 0 {
			slog.Info("audit exporter: replayed WAL entries", "count", len(pending))
		}
	}

	go ae.run()
	return ae
}

// Export queues an audit entry for export. The entry is persisted to the
// write-ahead log before entering the channel. Non-blocking; drops if the
// channel buffer is full, but the WAL copy survives a crash restart.
func (ae *AuditExporter) Export(entry *Entry) {
	if ae == nil {
		return
	}
	select {
	case <-ae.closed:
		return
	default:
	}

	// Persist to WAL before attempting channel send. On a crash restart,
	// WAL entries are replayed into the channel so no event is lost.
	if ae.wal != nil {
		if err := ae.wal.Append(entry); err != nil {
			slog.Error("audit exporter: WAL append failed", "action", entry.Action, "error", err)
		}
	}

	select {
	case ae.ch <- entry:
	case <-ae.closed:
	default:
		ae.dropped.Add(1)
		slog.Warn("audit exporter: dropping entry (channel full)",
			"action", entry.Action,
			"dropped_total", ae.dropped.Load(),
		)
	}
}

// Close signals the background goroutine to stop and waits for it to drain.
// After a clean drain, the WAL is truncated — all pending entries have been
// sent to the external system.
func (ae *AuditExporter) Close() {
	if ae == nil {
		return
	}
	ae.closeOnce.Do(func() {
		// Only close ae.closed — never close ae.ch here. Closing ae.ch while
		// Export() may concurrently be sending on it causes a race: Export's
		// two-step "check closed, then send" has a window where ae.ch gets
		// closed between the check and the send.
		close(ae.closed)
	})
	select {
	case <-ae.done:
	case <-time.After(5 * time.Second):
		slog.Warn("audit exporter drain timeout")
	}

	// Truncate WAL after clean drain. On crash, the WAL is preserved and
	// replayed on next startup.
	if ae.wal != nil {
		if err := ae.wal.Truncate(); err != nil {
			slog.Error("audit exporter: WAL truncate failed", "error", err)
		}
		if err := ae.wal.Close(); err != nil {
			slog.Error("audit exporter: WAL close failed", "error", err)
		}
	}
}

func (ae *AuditExporter) run() {
	defer close(ae.done)
	for {
		select {
		case entry := <-ae.ch:
			ae.send(entry)
		case <-ae.closed:
			// drain whatever is already buffered
			for {
				select {
				case entry := <-ae.ch:
					ae.send(entry)
				default:
					return
				}
			}
		}
	}
}

func (ae *AuditExporter) send(entry *Entry) {
	var body []byte
	var contentType string
	var err error

	switch ae.config.Format {
	case "splunk_hec":
		body, err = ae.formatSplunkHEC(entry)
		contentType = "application/json"
	case "syslog_cef":
		body, err = ae.formatCEF(entry)
		contentType = "text/plain"
	default: // "json"
		body, err = json.Marshal(entry)
		contentType = "application/json"
	}
	if err != nil {
		slog.Warn("audit export format error", "format", ae.config.Format, "error", err)
		return
	}

	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		// Build the request INSIDE the loop. It was previously constructed
		// once above and reused, but bytes.NewReader is drained by the first
		// Do() — so every retry sent an empty body and failed. The retry
		// logic looked correct and was guaranteed never to succeed, silently
		// dropping audit batches whenever the first attempt failed.
		req, err := http.NewRequest("POST", ae.config.Endpoint, bytes.NewReader(body))
		if err != nil {
			slog.Warn("audit export request error", "error", err)
			return
		}
		req.Header.Set("Content-Type", contentType)

		// Splunk HEC requires Authorization header
		if ae.config.Token != "" {
			req.Header.Set("Authorization", "Splunk "+ae.config.Token)
		}

		resp, err := ae.client.Do(req)
		if err != nil {
			slog.Warn("audit export POST failed", "attempt", attempt+1, "error", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			ae.exported.Add(1)
			return
		}
		if resp.StatusCode < 500 {
			slog.Warn("audit export client error", "status", resp.StatusCode)
			return
		}
		slog.Warn("audit export server error", "status", resp.StatusCode, "attempt", attempt+1)
	}
}

// SplunkHECEvent is the Splunk HTTP Event Collector event format.
type SplunkHECEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	SourceType string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

func (ae *AuditExporter) formatSplunkHEC(entry *Entry) ([]byte, error) {
	t, _ := time.Parse(time.RFC3339, entry.Timestamp)
	if t.IsZero() {
		t = time.Now()
	}

	event := map[string]interface{}{
		"action":     entry.Action,
		"network_id": entry.NetworkID,
		"node_id":    entry.NodeID,
	}
	if entry.Details != "" {
		event["details"] = entry.Details
	}

	hec := SplunkHECEvent{
		Time:       t.Unix(),
		Source:     ae.config.Source,
		SourceType: "pilot:audit",
		Index:      ae.config.Index,
		Event:      event,
	}
	if hec.Source == "" {
		hec.Source = "pilot-registry"
	}

	return json.Marshal(hec)
}

// cefEscape escapes |, =, \, \r, and \n characters as \|, \=, \\, \r, \n
// so that user-controlled fields cannot inject fake CEF headers or extensions.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// formatCEF produces a CEF (Common Event Format) line for SIEM ingestion.
// Format: CEF:0|Pilot|Registry|1.0|<action>|<action>|<severity>|<extensions>
func (ae *AuditExporter) formatCEF(entry *Entry) ([]byte, error) {
	severity := 3 // informational
	if strings.Contains(entry.Action, "kick") || strings.Contains(entry.Action, "delete") {
		severity = 6 // high
	} else if strings.Contains(entry.Action, "promote") || strings.Contains(entry.Action, "demote") {
		severity = 4 // medium
	}

	safeAction := cefEscape(entry.Action)

	extensions := fmt.Sprintf("dvc=pilot-registry dvchost=registry "+
		"cs1=%s cs1Label=action cn1=%d cn1Label=network_id cn2=%d cn2Label=node_id",
		safeAction, entry.NetworkID, entry.NodeID)

	if entry.Details != "" {
		extensions += fmt.Sprintf(" msg=%s", cefEscape(entry.Details))
	}

	line := fmt.Sprintf("CEF:0|Pilot|Registry|1.0|%s|%s|%d|%s",
		safeAction, safeAction, severity, extensions)

	return []byte(line), nil
}

// Stats returns export statistics.
func (ae *AuditExporter) Stats() (exported, dropped uint64) {
	if ae == nil {
		return 0, 0
	}
	return ae.exported.Load(), ae.dropped.Load()
}
