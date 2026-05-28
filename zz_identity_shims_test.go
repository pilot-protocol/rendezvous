// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
)

// TestServer_IdentityWebhookURL_SetGetRoundtrip exercises the thin
// delegation shims.
func TestServer_IdentityWebhookURL_SetGetRoundtrip(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.GetIdentityWebhookURL(); got != "" {
		t.Errorf("initial = %q, want empty", got)
	}
	s.SetIdentityWebhookURL("https://idp.example/verify")
	if got := s.GetIdentityWebhookURL(); got != "https://idp.example/verify" {
		t.Errorf("after set = %q", got)
	}
}

// TestServer_VerifyIdentityToken_NoWebhookReturnsEmpty exercises the
// short-circuit branch in the underlying Store.VerifyToken (no webhook
// configured → returns empty external ID with no error).
func TestServer_VerifyIdentityToken_NoWebhookReturnsEmpty(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	got, err := s.verifyIdentityToken("any-token")
	if err != nil {
		t.Errorf("err = %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestServer_GetIdentityProviderConfig_NilOnFreshServer exercises
// the nil-config branch.
func TestServer_GetIdentityProviderConfig_NilOnFreshServer(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	if got := s.GetIdentityProviderConfig(); got != nil {
		t.Errorf("fresh server: got %v, want nil", got)
	}
}

// TestServer_StoreRBACPreAssignments_PopulatesMap exercises the map-
// init + insert branches.
func TestServer_StoreRBACPreAssignments_PopulatesMap(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.storeRBACPreAssignments(7, []BlueprintRole{{ExternalID: "u1", Role: "admin"}})

	s.mu.RLock()
	roles, ok := s.rbacPreAssign[7]
	s.mu.RUnlock()
	if !ok || len(roles) != 1 || roles[0].Role != "admin" {
		t.Errorf("rbacPreAssign[7] = %+v", roles)
	}
}

// TestServer_EnableEnterpriseLocked_FlipsFlag exercises the flag-flip
// branch (network exists + currently non-enterprise).
func TestServer_EnableEnterpriseLocked_FlipsFlag(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "ADM")
	// Manually insert a network so the helper has a target.
	s.mu.Lock()
	netID := s.nextNet
	s.networks[netID] = &NetworkInfo{
		ID:          netID,
		Name:        "n",
		Enterprise:  false,
		MemberRoles: map[uint32]Role{},
	}
	s.nextNet++
	s.mu.Unlock()

	s.enableEnterpriseLocked(netID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.networks[netID].Enterprise {
		t.Error("Enterprise flag should be set")
	}
}

// TestServer_EnableEnterpriseLocked_UnknownNetworkIsNoOp covers the
// network-missing branch.
func TestServer_EnableEnterpriseLocked_UnknownNetworkIsNoOp(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	// No panic on missing netID.
	s.enableEnterpriseLocked(9999)
}

// TestServer_EnableEnterpriseLocked_AlreadyEnterpriseNoOp exercises the
// "already enterprise" branch (no save).
func TestServer_EnableEnterpriseLocked_AlreadyEnterpriseNoOp(t *testing.T) {
	t.Parallel()
	s := newTestServer(t, "")
	s.mu.Lock()
	netID := s.nextNet
	s.networks[netID] = &NetworkInfo{ID: netID, Name: "n", Enterprise: true}
	s.nextNet++
	s.mu.Unlock()

	s.enableEnterpriseLocked(netID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.networks[netID].Enterprise {
		t.Error("Enterprise flag should remain set")
	}
}
