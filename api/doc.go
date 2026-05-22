// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api defines the read-only view contracts that observability
// (dashboard, metrics, audit, webhook) and auth gates consume from the
// registry's state stores (directory, membership, trust, policy, identity).
//
// This package is the contract layer for the registry split. No
// implementations live here. Concrete stores in their own sub-packages
// satisfy these interfaces; consumers hold only the interface types,
// never the writeable *Store pointers.
//
// Stability contract: every exported identifier is part of the
// registry-internal layer-boundary ABI. Adding fields to the snapshot
// view structs is backward-compatible; renaming or removing them breaks
// every observability/auth consumer in lockstep with the store that
// produces the snapshot.
//
// Allowed imports: stdlib only (plus crypto/ed25519 and time when a
// view structurally needs them). No store-package imports — the import
// direction is consumer → api ← store.
package api
