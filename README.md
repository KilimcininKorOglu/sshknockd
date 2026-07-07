# sshknockd

[Türkçe](README.tr.md)

[![Packages](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml/badge.svg)](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml)
[![Latest Release](https://img.shields.io/github/v/release/KilimcininKoroglu/sshknockd?sort=semver)](https://github.com/KilimcininKoroglu/sshknockd/releases/latest)
[![Release Downloads](https://img.shields.io/github/downloads/KilimcininKoroglu/sshknockd/total)](https://github.com/KilimcininKoroglu/sshknockd/releases)
[![License](https://img.shields.io/github/license/KilimcininKoroglu/sshknockd)](LICENSE)

sshknockd is a lightweight server-side port knocking service for SSH access control. It keeps the SSH port closed until a source IP sends the configured knock sequence.

## Build

```sh
cargo build --release
```

## Test

```sh
cargo test
```

## Example configuration

See [sshknockd.toml](sshknockd.toml).

## Server configuration reference

| Setting                     |                    Default example | Meaning                                                                                     |
|-----------------------------|-----------------------------------:|---------------------------------------------------------------------------------------------|
| `listen`                    |                          `0.0.0.0` | Local address used by `sshknockd` for knock listeners. Use `::` for IPv6 listeners.         |
| `ssh_port`                  |                            `10022` | SSH TCP port that should be opened temporarily after a valid knock sequence.                |
| `ipset_name`                |                        `ssh_allow` | ipset set name used to hold temporarily allowed source IP addresses.                        |
| `firewall_backend`          |                         `iptables` | Firewall command family. Supported values are `iptables` for IPv4 and `ip6tables` for IPv6. |
| `address_family`            |                             `ipv4` | ipset address family. Supported values are `ipv4` and `ipv6`.                               |
| `sequence_window`           |                                `5` | Maximum seconds allowed from the first valid knock step to the final valid step.            |
| `ip_timeout`                |                               `10` | Seconds that a successfully knocking source IP remains allowed in ipset.                    |
| `partial_state_timeout`     |                               `10` | Seconds before incomplete per-source knock state is removed.                                |
| `max_payload_size`          |                              `512` | Maximum accepted knock payload size before the packet is treated as oversized.              |
| `log_level`                 |                             `info` | Audit verbosity. `info` logs security state changes; `debug` and `trace` add bounded packet telemetry. |
| `log_file`                  | `/var/log/sshknockd/sshknockd.log` | SIEM-oriented audit log file path.                                                          |
| `invalid_burst_limit`       |                               `20` | Invalid packet burst count allowed per source before ban logic is triggered.                |
| `invalid_refill_per_minute` |                               `10` | Invalid packet allowance restored per source every minute.                                  |
| `ban_timeout`               |                            `86400` | Seconds that a rate-limited source IP remains in the ban ipset.                             |
| `ban_ipset_name`            |                    `sshknockd_ban` | ipset set name used for 24-hour source IP bans.                                             |
| `knock.sequence[].protocol` |                              `udp` | Knock transport for a step. Supported values are `udp`, `tcp`, and `icmp`.                  |
| `knock.sequence[].port`     |                `0` until replaced | Destination port for `udp` and `tcp` steps. Replace placeholder ports before starting.       |
| `knock.sequence[].size`     |                       site-specific | Exact payload size required for the step.                                                   |

IPv4 uses `iptables` plus `ipset hash:ip`. IPv6 uses `ip6tables` plus `ipset hash:ip family inet6`.

OpenSSH is not required by sshknockd. The daemon protects a TCP port, so it can protect OpenSSH, Dropbear, or another SSH-compatible server listening on `ssh_port`. Install and configure your SSH server separately.

## Package builds

```sh
cargo install cargo-deb cargo-generate-rpm
cargo build --release
cargo deb
cargo generate-rpm
```

The packages include the `sshknockd(8)` man page and are built for `amd64` and `arm64` release targets. After installing a package, use `man sshknockd` for the daemon, administrative commands, and helper subcommands reference.

For clean local package output, remove stale artifacts or run `cargo clean` before rebuilding packages after renaming the package.

## Server installation

### Debian and Ubuntu

Download the latest `.deb` package from the `KilimcininKoroglu/sshknockd` GitHub releases page, then install it:

```sh
sudo apt-get update
sudo apt-get install -y ipset iptables curl
sudo dpkg -i ./sshknockd_0.1.0-1_amd64.deb
```

Use the package that matches your CPU architecture, for example `amd64` on x86_64 or `arm64` on ARM64.

### CentOS, Fedora, RHEL, Rocky Linux, and AlmaLinux

Download the latest `.rpm` package from the `KilimcininKoroglu/sshknockd` GitHub releases page, then install it:

```sh
sudo dnf install -y ipset iptables curl
sudo rpm -Uvh ./sshknockd-0.1.0-1.x86_64.rpm
```

Use your platform package manager if `dnf` is not available.

### Configure the server

Edit the installed configuration before opening firewall access:

```sh
sudo editor /etc/sshknockd.toml
```

The packaged configuration contains placeholder knock ports and will not start until you replace them. Set at least these values for your server:

- `listen`: address used by the knock listeners.
- `ssh_port`: the SSH server port to protect.
- `ipset_name`: temporary allowlist set.
- `ban_ipset_name`: rate-limit ban set.
- `invalid_burst_limit` and `invalid_refill_per_minute`: rate-limit policy.
- `ban_timeout`: ban duration in seconds.
- `knock.sequence`: deployment-specific protocol, port, and packet size sequence.

### Configure firewall rules

Run the setup command once after editing `/etc/sshknockd.toml`:

```sh
sudo sshknockd --config /etc/sshknockd.toml setup-firewall
```

The package does not change firewall rules during package installation. The `setup-firewall` command creates the allow ipset, creates the ban ipset, accepts matching allowlisted sources for the protected SSH port, drops other traffic to the protected SSH port, and drops traffic from rate-limited banned sources.

### Start the daemon

Enable and start the systemd service:

```sh
sudo systemctl enable --now sshknockd
sudo systemctl status sshknockd
```

Check audit logs:

```sh
sudo tail -f /var/log/sshknockd/sshknockd.log
```

The daemon writes SIEM-oriented audit events to `log_file`. At `info`, events include daemon startup, firewall preflight success or failure, listener binds, temporary SSH allow entries, rate-limit bans, and firewall command failures. `debug` and `trace` additionally enable bounded packet observations and knock outcomes with source IP plus redacted observation and outcome classes. Logs do not include knock protocol, knock port, packet size, sequence position, or the full knock sequence.

### Update

Update from the built-in GitHub repository and restart the service:

```sh
sudo sshknockd update
```

The command checks the latest release at `KilimcininKoroglu/sshknockd`, compares it with the installed version, selects a `.deb` package on Debian or Ubuntu and a `.rpm` package on CentOS, Fedora, RHEL, Rocky Linux, or AlmaLinux, verifies the downloaded package against the GitHub release asset `sha256` digest, installs it with `dpkg -i` or `rpm -Uvh`, then runs `systemctl restart sshknockd`.

Release assets must include the package extension and architecture in the file name. Debian or Ubuntu on x86_64 should publish a `.deb` asset containing `amd64`; RPM-based x86_64 systems should publish a `.rpm` asset containing `x86_64`. ARM64 systems should publish assets containing `arm64` or `aarch64`.

## Clientless knock examples

Replace every `<PORT*>` and `<SIZE*>` value with the deployment-specific sequence from `/etc/sshknockd.toml`.

```sh
printf '%0<SIZE1>s' '' | tr ' ' A | nc -u -w1 server.example.com <PORT1>
printf '%0<SIZE2>s' '' | tr ' ' B | nc -u -w1 server.example.com <PORT2>
printf '%0<SIZE3>s' '' | tr ' ' C | nc -u -w1 server.example.com <PORT3>
ssh -p 10022 user@server.example.com
```

```sshconfig
Host protected-server
    HostName server.example.com
    Port 10022
    User user
    ProxyCommand sh -c 'printf "%0<SIZE1>s" "" | tr " " A | nc -u -w1 %h <PORT1>; printf "%0<SIZE2>s" "" | tr " " B | nc -u -w1 %h <PORT2>; printf "%0<SIZE3>s" "" | tr " " C | nc -u -w1 %h <PORT3>; sleep 1; nc %h %p'
```
