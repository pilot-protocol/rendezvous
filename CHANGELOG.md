# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [v0.1.0]

Initial release.
