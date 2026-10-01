# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

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
