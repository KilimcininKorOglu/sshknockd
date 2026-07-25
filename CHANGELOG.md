# Changelog

## [0.2.4] - 2026-07-25

### Changed
- Overhaul README documentation structure.

### Fixed
- Make accepted TCP knock streams non-blocking so a slow or silent client can no longer stall the single-threaded poll loop.
- Stage updater downloads in a private root-only directory to prevent symlink attacks and verify/install races.
- Keep the daemon running when a ban ipset add fails, preventing a flood-induced crash loop.
- Correct ICMP knock payload size accounting for datagram sockets.
- Bind the ICMP knock listener to the configured address family (IPv4 or IPv6).
- Bound the in-memory banned source map so a spoofed-source flood cannot exhaust memory.

## [0.2.3] - 2026-07-08

### Fixed
- Remove client helper commands to keep sshknockd clientless.

## [0.2.2] - 2026-07-08

### Added
- Verify downloaded package integrity.

### Changed
- Cover daemon runtime packet handling.
- Scope release permissions and package metadata checks.
- Add multi-architecture package release support and custom release notes.
- Include README files in package assets.
- Standardize project naming and configuration file naming.
- Apply Rust formatting.

### Fixed
- Pin release packaging tools.
- Bound partial knock state entries, packet telemetry logs, updater HTTP timeouts, and idle rate limiter buckets.
- Bind release artifacts to expected outputs.
- Pin release workflow actions.
- Enforce HTTPS for updater downloads.
- Require deployment-specific knock sequences and signed update checksums.
- Redact audit telemetry details.
- Reject SSH port knock listener overlap and unknown config fields.
- Separate invalid knock source bans and expire in-memory source bans.
- Quote generated print-script arguments.
- Surface audit log write failures.
- Make firewall setup idempotent and include firewall command diagnostics.
- Add TCP knock read timeout.

## [0.2.1] - 2026-07-07

### Changed
- Consolidate the helper client into the sshknockd daemon binary.

## [0.2.0] - 2026-07-07

### Added
- Initial sshknockd implementation.

### Changed
- Add project badges to README files.
- Fix Turkish README configuration table formatting.
