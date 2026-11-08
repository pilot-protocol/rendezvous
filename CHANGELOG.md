# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- A node without a public key can no longer be acted for by anyone:
  `request_handshake` and `respond_handshake` skipped verification for such
  a node, so any caller could mint a trust pair in its name. Both now need the
  admin token for it, like every other authenticated handler, and the
  snapshot and replication loaders never load a node whose key isn't a valid
  Ed25519 key.
- A trust pair now needs both nodes' consent. `report_trust` is signed by
  one node, yet it wrote the symmetric pair by itself, so one node could make
  a private node admit its streams and datagrams and resolve that node's
  endpoint. A report is now a claim that waits (up to 30 days, at most 10,000
  per node) for the other node's own `report_trust`; then the pair is written.
  The signed handshake relay and a keyless node's admin-token report write the
  pair in one step as before. A waiting report answers `report_trust_ok` with
  `"trusted": false`. Either node may still revoke alone, which also
  withdraws its waiting claim.
- Role-based network administration now requires proof of identity. A
  `delete_network`, `rename_network`, `kick_member`, `promote_member`,
  `demote_member`, `transfer_ownership`, `set_member_tags`,
  `set_network_policy` or `set_expr_policy` request that is authorized by the
  role of its `node_id` (rather than by the global or per-network admin token)
  must carry a `signature` by that node's registered Ed25519 key over a
  challenge binding the operation, node, network and argument
  (`authz.NetworkRoleChallenge`). Previously the `node_id` was taken on trust.
  Nodes registered without a key need an admin token. Admin-token callers are
  unaffected.
- A reaped node's id is no longer handed to a new key on the strength of its
  owner string. Reaping keeps the id's network roles and trust pairs so the
  node can resume; previously any `register` presenting the same `owner`
  with a different key resumed it. Such a registration is now refused unless
  it carries the global admin token. Re-registering with the original key is
  unchanged.

### Added

- Relayed trust handshakes no longer wait for the recipient's next poll. When
  `request_handshake` or `respond_handshake` parks a message for a node, the
  registry tells its co-located beacon (`SetHandshakeNotifier`, wired in
  `cmd/rendezvous` when the beacon has `NotifyNode`), which sends that node a
  two-byte notify; an updated daemon then polls at once. The notify carries
  nothing about the handshake or the other node. Older daemons ignore it and
  poll once a minute as before.
- `resolve_hostname_ok` carries `last_seen_unix`, the same field `lookup_ok`
  reports, so a caller can tell a hostname held by a node that has stopped
  heartbeating from a live one. Additive; hostname claimability and
  resolution are unchanged.
- `-allow-unsigned-network-role-auth` (env
  `RENDEZVOUS_ALLOW_UNSIGNED_NETWORK_ROLE_AUTH=1`), off by default: a
  migration escape hatch that accepts unsigned role claims again for nodes
  that have not yet signed one. It restores the insecure behaviour and logs a
  warning at startup and on every unsigned acceptance.

## [v0.1.0]

Initial release.
