// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// fakeView with controllable nodes is reused from zz_store_test.go via
// fakeNodeView; here we extend it to support CheckAdminToken behaviors.

// adminCheckingView wraps fakeNodeView to control admin-token responses.
type adminCheckingView struct {
	*fakeNodeView
	adminOK bool
}

func (v *adminCheckingView) CheckAdminToken(map[string]interface{}) error {
	if v.adminOK {
		return nil
	}
	return errors.New("admin required")
}

func newAdminStore(t *testing.T, nodes map[uint32]fakeNode, adminOK bool) *Store {
	t.Helper()
	view := &adminCheckingView{
		fakeNodeView: &fakeNodeView{nodes: nodes},
		adminOK:      adminOK,
	}
	return NewStore(view, Callbacks{
		Save:                func() {},
		Audit:               func(string, ...any) {},
		IncKeyRotations:     func() {},
		IncIDPVerifications: func() {},
		RecordWAL:           func(uint32, string, string) {},
		OnKeyRotated:        func(uint32, string, string) {},
	})
}

func TestHandleGetKeyInfo_HappyPath(t *testing.T) {
	t.Parallel()
	now := time.Now()
	st := newAdminStore(t, map[uint32]fakeNode{
		42: {
			keyMeta: KeyInfo{
				CreatedAt:   now.Add(-30 * 24 * time.Hour),
				RotatedAt:   now.Add(-7 * 24 * time.Hour),
				RotateCount: 2,
				ExpiresAt:   now.Add(60 * 24 * time.Hour),
			},
		},
	}, true)

	resp, err := st.HandleGetKeyInfo(map[string]interface{}{
		"node_id": float64(42),
	})
	if err != nil {
		t.Fatalf("HandleGetKeyInfo: %v", err)
	}
	if resp["rotate_count"] != 2 {
		t.Errorf("rotate_count = %v", resp["rotate_count"])
	}
	if _, ok := resp["rotated_at"]; !ok {
		t.Error("rotated_at missing")
	}
	if _, ok := resp["expires_at"]; !ok {
		t.Error("expires_at missing")
	}
	if _, ok := resp["key_age_days"]; !ok {
		t.Error("key_age_days missing")
	}
}

func TestHandleGetKeyInfo_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleGetKeyInfo(map[string]interface{}{"node_id": float64(9999)})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandleGetIdentity_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{1: {externalID: "ext-1", owner: "alice"}}, false)
	_, err := st.HandleGetIdentity(map[string]interface{}{"node_id": float64(1)})
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleGetIdentity_HappyAndUnknown(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{1: {externalID: "ext-1", owner: "alice"}}, true)

	resp, err := st.HandleGetIdentity(map[string]interface{}{"node_id": float64(1)})
	if err != nil {
		t.Fatalf("HandleGetIdentity: %v", err)
	}
	if resp["external_id"] != "ext-1" {
		t.Errorf("external_id = %v", resp["external_id"])
	}

	if _, err := st.HandleGetIdentity(map[string]interface{}{"node_id": float64(9999)}); err == nil {
		t.Error("expected unknown-node error")
	}
}

func TestHandleSetIdentityWebhook_EnableAndDisable(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)

	resp, err := st.HandleSetIdentityWebhook(map[string]interface{}{"url": "https://idp/verify"})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if resp["status"] != "enabled" {
		t.Errorf("status = %v, want enabled", resp["status"])
	}

	resp, _ = st.HandleSetIdentityWebhook(map[string]interface{}{"url": ""})
	if resp["status"] != "disabled" {
		t.Errorf("status = %v, want disabled", resp["status"])
	}
}

func TestHandleSetIdentityWebhook_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	_, err := st.HandleSetIdentityWebhook(map[string]interface{}{"url": "https://x"})
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleSetIDPConfig_DisableWithEmptyType(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	resp, err := st.HandleSetIDPConfig(map[string]interface{}{
		"idp_type": "",
		"url":      "",
	})
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if resp["status"] != "disabled" {
		t.Errorf("status = %v, want disabled", resp["status"])
	}
}

func TestHandleSetIDPConfig_EnableWithAllFields(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	resp, err := st.HandleSetIDPConfig(map[string]interface{}{
		"idp_type":  "oidc",
		"url":       "https://idp.example/jwks",
		"issuer":    "https://idp.example",
		"client_id": "client-1",
		"tenant_id": "tenant-1",
		"domain":    "example.com",
	})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if resp["idp_type"] != "oidc" {
		t.Errorf("idp_type = %v", resp["idp_type"])
	}
}

func TestHandleSetIDPConfig_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	_, err := st.HandleSetIDPConfig(map[string]interface{}{})
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleGetIDPConfig_NotConfigured(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	resp, err := st.HandleGetIDPConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("HandleGetIDPConfig: %v", err)
	}
	if resp["configured"] != false {
		t.Errorf("configured = %v, want false", resp["configured"])
	}
}

func TestHandleGetIDPConfig_ConfiguredReturnsFields(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	st.SetIDPConfig(&wire.BlueprintIdentityProvider{
		Type:     "oidc",
		URL:      "https://idp/jwks",
		Issuer:   "https://idp",
		ClientID: "c1",
		TenantID: "t1",
		Domain:   "example.com",
	})

	resp, err := st.HandleGetIDPConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("HandleGetIDPConfig: %v", err)
	}
	if resp["configured"] != true {
		t.Errorf("configured = %v, want true", resp["configured"])
	}
	for _, k := range []string{"idp_type", "url", "issuer", "client_id", "tenant_id", "domain"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("field %q missing", k)
		}
	}
}

func TestHandleGetIDPConfig_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	if _, err := st.HandleGetIDPConfig(map[string]interface{}{}); err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleGetProvisionStatus_HappyPath(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	resp, err := st.HandleGetProvisionStatus(
		map[string]interface{}{},
		func() []map[string]interface{} {
			return []map[string]interface{}{{"network_id": 1, "name": "n1"}}
		},
		true, "splunk_hec",
	)
	if err != nil {
		t.Fatalf("HandleGetProvisionStatus: %v", err)
	}
	if _, ok := resp["networks"]; !ok {
		t.Error("networks field missing")
	}
}

func TestHandleGetProvisionStatus_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	_, err := st.HandleGetProvisionStatus(
		map[string]interface{}{},
		func() []map[string]interface{} { return nil },
		false, "",
	)
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleSetExternalID_AuthRequired(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, false)
	_, err := st.HandleSetExternalID(map[string]interface{}{"node_id": float64(1)})
	if err == nil {
		t.Error("expected admin-required error")
	}
}

func TestHandleSetExternalID_UnknownNode(t *testing.T) {
	t.Parallel()
	st := newAdminStore(t, map[uint32]fakeNode{}, true)
	_, err := st.HandleSetExternalID(map[string]interface{}{
		"node_id":     float64(9999),
		"external_id": "ext-x",
	})
	if err == nil {
		t.Error("expected unknown-node error")
	}
}

// TestNewJWKSCache_Internal exercises the unexported newJWKSCache helper.
func TestNewJWKSCache_Internal(t *testing.T) {
	t.Parallel()
	c := newJWKSCache()
	if c == nil {
		t.Fatal("nil cache")
	}
	if c.TTL == 0 {
		t.Error("TTL not initialized")
	}
}

// TestHashOwner produces a stable hash for an owner string.
func TestHashOwner_Stable(t *testing.T) {
	t.Parallel()
	a := HashOwner("alice@example.com")
	b := HashOwner("alice@example.com")
	if a == "" {
		t.Error("HashOwner empty")
	}
	if a != b {
		t.Error("HashOwner not deterministic")
	}
	if HashOwner("bob@example.com") == a {
		t.Error("different owners should hash differently")
	}
}

// TestBase64Decode covers the small helper.
func TestBase64Decode_HappyAndError(t *testing.T) {
	t.Parallel()
	got, err := base64Decode("aGVsbG8=")
	if err != nil || string(got) != "hello" {
		t.Errorf("happy: got (%q, %v)", got, err)
	}
	if _, err := base64Decode("!!!"); err == nil {
		t.Error("expected b64 error")
	}
}
