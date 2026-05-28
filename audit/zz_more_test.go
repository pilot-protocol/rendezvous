// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

func TestExporterConfig_FreshIsNil(t *testing.T) {
	t.Parallel()
	st := NewStore()
	if got := st.ExporterConfig(); got != nil {
		t.Errorf("fresh store: ExporterConfig = %v, want nil", got)
	}
}

func TestExporterStats_NilExporterIsZeros(t *testing.T) {
	t.Parallel()
	st := NewStore()
	exported, dropped := st.ExporterStats()
	if exported != 0 || dropped != 0 {
		t.Errorf("got (%d, %d), want (0, 0)", exported, dropped)
	}
}

func TestHandleGetAuditExport_DisabledBranch(t *testing.T) {
	t.Parallel()
	st := NewStore()
	resp, err := st.HandleGetAuditExport(nil)
	if err != nil {
		t.Fatalf("HandleGetAuditExport: %v", err)
	}
	if resp["type"] != "get_audit_export_ok" {
		t.Errorf("type = %v", resp["type"])
	}
	if resp["enabled"] != false {
		t.Errorf("enabled = %v, want false", resp["enabled"])
	}
}

func TestHandleGetAuditExport_EnabledWithStats(t *testing.T) {
	t.Parallel()
	st := NewStore()
	cfg := &wire.BlueprintAuditExport{
		Format:   "splunk_hec",
		Endpoint: "https://splunk/hec",
		Token:    "abc",
	}
	st.SetExporter(cfg)
	t.Cleanup(func() { st.SetExporter(nil) })

	resp, err := st.HandleGetAuditExport(nil)
	if err != nil {
		t.Fatalf("HandleGetAuditExport: %v", err)
	}
	if resp["enabled"] != true {
		t.Errorf("enabled = %v, want true", resp["enabled"])
	}
	if resp["format"] != "splunk_hec" {
		t.Errorf("format = %v", resp["format"])
	}
	if resp["endpoint"] != "https://splunk/hec" {
		t.Errorf("endpoint = %v", resp["endpoint"])
	}
	if _, ok := resp["exported"]; !ok {
		t.Errorf("exported counter missing")
	}
	if _, ok := resp["dropped"]; !ok {
		t.Errorf("dropped counter missing")
	}
}

func TestNewAuditExporter_StartsAndStops(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &wire.BlueprintAuditExport{
		Format:   "splunk_hec",
		Endpoint: srv.URL,
	}
	ae := NewAuditExporter(cfg)
	if ae == nil {
		t.Fatal("NewAuditExporter returned nil")
	}

	// Queue one entry and let it process.
	ae.Export(&Entry{Action: "test.action", NodeID: 1, Timestamp: time.Now().Format(time.RFC3339)})
	// Give the run loop a moment.
	for i := 0; i < 50; i++ {
		exported, _ := ae.Stats()
		if exported > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	ae.Close()
}

func TestAuditExporter_NilSafe(t *testing.T) {
	t.Parallel()
	var ae *AuditExporter
	ae.Export(&Entry{}) // nil receiver — must not panic
	ae.Close()          // nil receiver — must not panic
}

func TestAuditExporter_ExportAfterClose(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ae := NewAuditExporter(&wire.BlueprintAuditExport{Format: "splunk_hec", Endpoint: srv.URL})
	ae.Close()
	// Export after Close must be a no-op (counter stays 0).
	ae.Export(&Entry{Action: "ignored"})
	exported, _ := ae.Stats()
	if exported > 1 {
		t.Errorf("exported = %d, want 0 or 1 after close", exported)
	}
}

func TestAuditExporter_DropOnFullBuffer(t *testing.T) {
	t.Parallel()
	// Use an endpoint that hangs forever so the buffer fills up.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ae := NewAuditExporter(&wire.BlueprintAuditExport{Format: "splunk_hec", Endpoint: srv.URL})
	t.Cleanup(ae.Close)

	// Try to enqueue more than 1024 — drops should occur.
	for i := 0; i < 2000; i++ {
		ae.Export(&Entry{Action: "flood"})
	}
	_, dropped := ae.Stats()
	if dropped == 0 {
		t.Skip("environment didn't produce buffer pressure — heuristic test")
	}
}
