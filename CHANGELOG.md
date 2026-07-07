# Changelog

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
