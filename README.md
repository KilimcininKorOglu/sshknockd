# sshknockd

[Türkçe](README.tr.md)

[![Packages](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml/badge.svg)](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml)
[![Latest Release](https://img.shields.io/github/v/release/KilimcininKoroglu/sshknockd?sort=semver)](https://github.com/KilimcininKoroglu/sshknockd/releases/latest)
[![Release Downloads](https://img.shields.io/github/downloads/KilimcininKoroglu/sshknockd/total)](https://github.com/KilimcininKoroglu/sshknockd/releases)
[![License](https://img.shields.io/github/license/KilimcininKoroglu/sshknockd)](LICENSE)

`sshknockd` is a lightweight server-side port knocking daemon for SSH access control. It keeps the protected SSH port closed until a source IP sends a configured knock sequence, then temporarily allows that source through `ipset` and `iptables`. The daemon reduces the exposure of the SSH port to untargeted internet scanning and automated brute-force traffic.

## Features

- Clientless by design. Clients reproduce the knock sequence with standard tools such as `nc`, shell redirection, `ping`, or an SSH `ProxyCommand`. No dedicated client binary is required.
- Multi-protocol knock steps over UDP, TCP, and ICMP, each with a required exact payload size.
- Source-IP-bound sequence state with a bounded time window and a capacity limit on concurrent partial states.
- Per-source rate limiting with a token bucket. Abusive sources are moved into a ban `ipset` for a configurable duration.
- IPv4 and IPv6 support through `iptables` plus `ipset hash:ip` and `ip6tables` plus `ipset hash:ip family inet6`.
- SIEM-oriented audit logging that never records the knock sequence or enough detail to reconstruct it.
- Self-update from signed GitHub release packages, verified against an embedded ed25519 key.
- Distributed as Debian and RPM packages for `amd64` and `arm64`, with a `systemd` unit and a `sshknockd(8)` man page.

## How it works

1. The daemon binds listeners for every protocol and port in the configured sequence.
2. A source IP must send each knock step in order, with the correct protocol, destination port, and exact payload size, within `sequence_window` seconds.
3. On a complete match, the source IP is added to the allow `ipset` with a timeout of `ip_timeout` seconds. The firewall accepts that source on the protected SSH port for the duration.
4. Wrong protocol, wrong port, wrong size, or a timeout resets the partial sequence state for that source.
5. Sources that exceed the invalid-attempt rate limit are banned through the ban `ipset` for `ban_timeout` seconds.

The knock sequence is not authentication. A captured sequence can be replayed from a compatible network path. SSH authentication remains the real security boundary.

## Requirements

- Linux with `iptables` (or `ip6tables`), `ipset`, and `curl` available.
- Root privileges for the daemon, because it manages firewall rules.
- An SSH server such as OpenSSH or Dropbear listening on the protected `ssh_port`. `sshknockd` does not embed or modify SSH; install and configure the SSH server separately.

## Installation

Download the package that matches your CPU architecture from the [releases page](https://github.com/KilimcininKoroglu/sshknockd/releases/latest). Use `amd64` (`.deb`) or `x86_64` (`.rpm`) on x86_64, and `arm64` (`.deb`) or `aarch64` (`.rpm`) on ARM64.

### Debian and Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y ipset iptables curl
sudo dpkg -i ./sshknockd_<version>_amd64.deb
```

### CentOS, Fedora, RHEL, Rocky Linux, and AlmaLinux

```sh
sudo dnf install -y ipset iptables curl
sudo rpm -Uvh ./sshknockd-<version>.x86_64.rpm
```

Use your platform package manager if `dnf` is not available. Installing the package does not change any firewall rules. It installs the binary, the default `/etc/sshknockd.toml`, the `systemd` unit, and the man page.

## Quick start

```sh
# 1. Edit the configuration and replace the placeholder knock ports.
sudo editor /etc/sshknockd.toml

# 2. Create the ipsets and firewall rules once.
sudo sshknockd --config /etc/sshknockd.toml setup-firewall

# 3. Enable and start the daemon.
sudo systemctl enable --now sshknockd

# 4. Watch the audit log.
sudo tail -f /var/log/sshknockd/sshknockd.log
```

The packaged configuration ships with placeholder knock ports set to `0` and will not start until you replace them.

## Configuration

The example configuration is [sshknockd.toml](sshknockd.toml). The installed path is `/etc/sshknockd.toml`.

### Server settings

| Setting                     |                    Default example | Meaning                                                                                     |
|-----------------------------|-----------------------------------:|---------------------------------------------------------------------------------------------|
| `listen`                    |                          `0.0.0.0` | Local address used by the knock listeners. Use `::` for IPv6 listeners.                     |
| `ssh_port`                  |                            `10022` | SSH TCP port that is opened temporarily after a valid knock sequence.                       |
| `ipset_name`                |                        `ssh_allow` | ipset set name that holds temporarily allowed source IP addresses.                          |
| `firewall_backend`          |                         `iptables` | Firewall command family. Supported values are `iptables` for IPv4 and `ip6tables` for IPv6. |
| `address_family`            |                             `ipv4` | ipset address family. Supported values are `ipv4` and `ipv6`.                               |
| `sequence_window`           |                                `5` | Maximum seconds from the first valid knock step to the final valid step (1 to 60).          |
| `ip_timeout`                |                               `10` | Seconds that a successfully knocking source IP remains allowed in ipset.                    |
| `partial_state_timeout`     |                               `10` | Seconds before incomplete per-source knock state is removed.                                |
| `max_partial_states`        |                             `4096` | Maximum number of concurrent incomplete per-source knock states.                            |
| `max_payload_size`          |                              `512` | Maximum accepted knock payload size before the packet is treated as oversized.              |
| `log_level`                 |                             `info` | Audit verbosity. `info` logs security state changes; `debug` and `trace` add bounded packet telemetry. |
| `log_file`                  | `/var/log/sshknockd/sshknockd.log` | SIEM-oriented audit log file path.                                                          |
| `invalid_burst_limit`       |                               `20` | Invalid packet burst count allowed per source before ban logic is triggered.                |
| `invalid_refill_per_minute` |                               `10` | Invalid packet allowance restored per source every minute.                                  |
| `ban_timeout`               |                            `86400` | Seconds that a rate-limited source IP remains in the ban ipset.                             |
| `ban_ipset_name`            |                    `sshknockd_ban` | ipset set name used for source IP bans.                                                     |

### Knock sequence

The sequence must contain at least three steps. Each step requires a protocol and an exact payload size. TCP and UDP steps also require a destination port.

| Setting                     |             Default example | Meaning                                                              |
|-----------------------------|----------------------------:|----------------------------------------------------------------------|
| `knock.sequence[].protocol` |                       `udp` | Knock transport for a step. Supported values are `udp`, `tcp`, and `icmp`. |
| `knock.sequence[].port`     |           `0` until replaced | Destination port for `udp` and `tcp` steps. Omit for `icmp`. `0` is rejected. |
| `knock.sequence[].size`     |                site-specific | Exact payload size required for the step, from 1 to `max_payload_size`. |

The daemon validates the configuration at startup and rejects unknown fields, so a typo cannot silently change the security posture. TCP and UDP ports must be unique and must not overlap `ssh_port`. IPv4 uses `iptables` plus `ipset hash:ip`; IPv6 uses `ip6tables` plus `ipset hash:ip family inet6`.

## Firewall setup

Run the setup command once after editing `/etc/sshknockd.toml`:

```sh
sudo sshknockd --config /etc/sshknockd.toml setup-firewall
```

The command creates the allow ipset, creates the ban ipset, accepts matching allowlisted sources on the protected SSH port, drops other traffic to the protected SSH port, and drops traffic from rate-limited banned sources. Firewall rules are not changed during package installation.

## Audit logging

The daemon writes SIEM-oriented audit events to `log_file`. At `info`, events include daemon startup, firewall preflight success or failure, listener binds, temporary SSH allow entries, rate-limit bans, and firewall command failures. `debug` and `trace` add bounded packet observations and knock outcomes with the source IP plus redacted observation and outcome classes. Logs never include the knock protocol, knock port, packet size, sequence position, or the full knock sequence.

## Updating

```sh
sudo sshknockd update
```

The command checks the latest release at `KilimcininKoroglu/sshknockd`, compares it with the installed version, and selects a `.deb` package on Debian or Ubuntu and a `.rpm` package on CentOS, Fedora, RHEL, Rocky Linux, or AlmaLinux. It restricts package, checksum, and signature downloads to HTTPS including redirects, verifies the signed `SHA256SUMS` manifest with an embedded ed25519 public key, verifies the downloaded package against its manifest `sha256` digest, installs it with `dpkg -i` or `rpm -Uvh`, and then runs `systemctl restart sshknockd`. Downloads are staged in a per-process, root-only temporary directory that is removed after installation or on error.

Release asset names must include the package extension and architecture. x86_64 Debian or Ubuntu publishes a `.deb` asset containing `amd64`; RPM-based x86_64 systems publish a `.rpm` asset containing `x86_64`. ARM64 systems publish assets containing `arm64` or `aarch64`.

## Clientless knock examples

Replace every `<PORT*>` and `<SIZE*>` value with the deployment-specific sequence from `/etc/sshknockd.toml`.

```sh
printf '%0<SIZE1>s' '' | tr ' ' A | nc -u -w1 server.example.com <PORT1>
printf '%0<SIZE2>s' '' | tr ' ' B | nc -u -w1 server.example.com <PORT2>
printf '%0<SIZE3>s' '' | tr ' ' C | nc -u -w1 server.example.com <PORT3>
ssh -p 10022 user@server.example.com
```

The same sequence works as an SSH `ProxyCommand`, so `ssh` sends the knock automatically before connecting:

```sshconfig
Host protected-server
    HostName server.example.com
    Port 10022
    User user
    ProxyCommand sh -c 'printf "%0<SIZE1>s" "" | tr " " A | nc -u -w1 %h <PORT1>; printf "%0<SIZE2>s" "" | tr " " B | nc -u -w1 %h <PORT2>; printf "%0<SIZE3>s" "" | tr " " C | nc -u -w1 %h <PORT3>; sleep 1; nc %h %p'
```

## Building from source

```sh
cargo build --release --locked
cargo test --all-targets --locked
```

Build local packages:

```sh
cargo install cargo-deb --version 3.7.0
cargo install cargo-generate-rpm --version 0.18.0 --locked
cargo build --release --locked
cargo deb --no-build
cargo generate-rpm
```

The packages are built for `amd64` and `arm64` and include the `sshknockd(8)` man page. After installing a package, run `man sshknockd` for the daemon and administrative command reference. Remove stale artifacts or run `cargo clean` before rebuilding packages after renaming the package.

## Commands

| Command | Purpose |
|---|---|
| `sshknockd --config <path>` | Start the daemon with the given configuration. |
| `sshknockd --config <path> setup-firewall` | Create the ipsets and firewall rules for the protected SSH port. |
| `sshknockd --config <path> config` | Print a short summary of the loaded configuration. |
| `sshknockd update` | Download, verify, install, and activate the latest release package. |
| `sshknockd version` | Print the installed version. |

## Security notes

- The knock sequence is obfuscation, not authentication. Keep SSH authentication strong.
- The daemon runs as root to manage the firewall. The packaged `systemd` unit applies hardening options such as `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`, and `MemoryDenyWriteExecute`.
- Firewall commands are executed with explicit arguments and never through a shell, so configuration values cannot inject commands.

## License

Licensed under the [Apache License 2.0](LICENSE).

