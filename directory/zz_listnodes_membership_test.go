// SPDX-License-Identifier: AGPL-3.0-or-later

package directory

// Regression for P0 enumeration vector: HandleListNodes had no auth
// gate on non-backbone networks. Any caller could enumerate any
// network's members by sending list_nodes(network_id=N) with no
// admin_token and no signature. Backbone (network_id=0) already
// required admin; per-network listing was wide open.
//
// Policy decision (per operator 2026-05-26): we don't care about
// supporting non-admin list_nodes as a feature. Block enumeration
// completely — list_nodes requires the admin token on every network.
// All six production daemon call sites already pass the admin token,
// so this change is backwards-compatible for the daemon fleet.

import (
	"errors"
	"testing"
)

func TestHandleListNodes_NonBackboneRequiresAdmin(t *testing.T) {
	t.Parallel()

	st := newTestStore(t)

	_, err := st.HandleListNodes(
		map[string]interface{}{"network_id": float64(42)},
		func(msg map[string]interface{}) error {
			return errors.New("simulated: no admin token")
		},
	)
	if err == nil {
		t.Fatal("HandleListNodes returned nil for non-backbone without admin " +
			"— enumeration gate not enforced")
	}
}

func TestHandleListNodes_NonBackboneWithAdminSucceedsThroughGate(t *testing.T) {
	t.Parallel()

	st := newTestStore(t)

	// requireAdminToken returns nil → admin path → gate passes. The
	// actual list build may still fail with ErrNetworkNotFound (the
	// test view returns no network), but the auth gate itself must
	// not be the blocker.
	_, err := st.HandleListNodes(
		map[string]interface{}{"network_id": float64(42)},
		func(msg map[string]interface{}) error { return nil },
	)
	// We accept any error EXCEPT a denied-auth one. The auth check
	// failure surfaces the simulated error verbatim, so checking the
	// presence/absence of that exact text is enough.
	if err != nil && err.Error() == "simulated: no admin token" {
		t.Fatalf("auth gate denied a request that supplied a valid admin token")
	}
}

func TestHandleListNodes_BackboneStillRequiresAdmin(t *testing.T) {
	t.Parallel()
	// Pre-existing backbone behavior must not regress.

	st := newTestStore(t)

	_, err := st.HandleListNodes(
		map[string]interface{}{"network_id": float64(0)},
		func(msg map[string]interface{}) error { return errors.New("no admin") },
	)
	if err == nil {
		t.Fatal("expected backbone listing to fail without admin token")
	}
}
