# sshknockd

[English](README.md)

[![Packages](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml/badge.svg)](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml)
[![Son Release](https://img.shields.io/github/v/release/KilimcininKoroglu/sshknockd?sort=semver)](https://github.com/KilimcininKoroglu/sshknockd/releases/latest)
[![Release Downloads](https://img.shields.io/github/downloads/KilimcininKoroglu/sshknockd/total)](https://github.com/KilimcininKoroglu/sshknockd/releases)
[![License](https://img.shields.io/github/license/KilimcininKoroglu/sshknockd)](LICENSE)

sshknockd, SSH erişim kontrolü için hafif bir server-side port knocking servisidir. Kaynak IP yapılandırılmış knock sequence göndermeden SSH portunu kapalı tutar.

## Build

```sh
cargo build --release
```

## Test

```sh
cargo test
```

## Örnek yapılandırma

[sshknockd.toml](sshknockd.toml) dosyasına bakın.

## Server yapılandırma referansı

| Ayar                        |                   Varsayılan örnek | Anlamı                                                                                 |
|-----------------------------|-----------------------------------:|----------------------------------------------------------------------------------------|
| `listen`                    |                          `0.0.0.0` | `sshknockd` knock listener adresi. IPv6 listener için `::` kullanın.                   |
| `ssh_port`                  |                            `10022` | Geçerli knock sequence sonrasında geçici olarak açılacak SSH TCP portu.                |
| `ipset_name`                |                        `ssh_allow` | Geçici izin verilen source IP adreslerini tutan ipset adı.                             |
| `firewall_backend`          |                         `iptables` | Firewall komut ailesi. IPv4 için `iptables`, IPv6 için `ip6tables`.                    |
| `address_family`            |                             `ipv4` | ipset address family. Desteklenen değerler `ipv4` ve `ipv6`.                           |
| `sequence_window`           |                                `5` | İlk geçerli knock step ile son geçerli step arasında izin verilen maksimum saniye.     |
| `ip_timeout`                |                               `10` | Başarılı knock yapan source IP adresinin ipset içinde izinli kalacağı saniye.          |
| `partial_state_timeout`     |                               `10` | Eksik per-source knock state temizlenmeden önce beklenecek saniye.                     |
| `max_payload_size`          |                              `512` | Packet oversized sayılmadan önce kabul edilen maksimum knock payload size.             |
| `log_level`                 |                             `info` | Audit verbosity. `info` security state change’leri loglar; `debug` ve `trace` bounded packet telemetry ekler. |
| `log_file`                  | `/var/log/sshknockd/sshknockd.log` | SIEM odaklı audit log dosya yolu.                                                      |
| `invalid_burst_limit`       |                               `20` | Ban mantığı tetiklenmeden önce source başına izin verilen invalid packet burst değeri. |
| `invalid_refill_per_minute` |                               `10` | Source başına her dakika geri eklenen invalid packet hakkı.                            |
| `ban_timeout`               |                            `86400` | Rate limit’e takılan source IP’nin ban ipset içinde kalacağı saniye.                   |
| `ban_ipset_name`            |                    `sshknockd_ban` | 24 saatlik source IP ban’leri için kullanılan ipset adı.                               |
| `knock.sequence[].protocol` |                              `udp` | Step için knock transport. Desteklenen değerler `udp`, `tcp` ve `icmp`.                |
| `knock.sequence[].port`     |          değiştirilene kadar `0` | `udp` ve `tcp` step’leri için destination port. Başlatmadan önce placeholder portları değiştirin. |
| `knock.sequence[].size`     |                    site-specific | Step için gereken tam payload size.                                                    |

IPv4, `iptables` ve `ipset hash:ip` kullanır. IPv6, `ip6tables` ve `ipset hash:ip family inet6` kullanır.

OpenSSH, sshknockd için zorunlu değildir. Daemon bir TCP portunu korur, bu yüzden OpenSSH, Dropbear veya `ssh_port` üzerinde dinleyen başka bir SSH-compatible server korunabilir. SSH server’ınızı ayrıca kurun ve yapılandırın.

## Paket build

```sh
cargo install cargo-deb cargo-generate-rpm
cargo build --release
cargo deb
cargo generate-rpm
```

Paketler `sshknockd(8)` man sayfasını içerir ve `amd64` ile `arm64` release target’ları için build edilir. Paket kurulduktan sonra daemon, administrative command ve helper subcommand reference için `man sshknockd` kullanın.

Temiz local package çıktısı için package adı değiştikten sonra stale artifact’leri kaldırın veya paketleri yeniden build etmeden önce `cargo clean` çalıştırın.

## Server kurulumu

### Debian ve Ubuntu

`KilimcininKoroglu/sshknockd` GitHub releases sayfasından son `.deb` paketini indirin ve kurun:

```sh
sudo apt-get update
sudo apt-get install -y ipset iptables curl
sudo dpkg -i ./sshknockd_0.1.0-1_amd64.deb
```

CPU architecture’ınıza uygun paketi kullanın, örneğin x86_64 için `amd64`, ARM64 için `arm64`.

### CentOS, Fedora, RHEL, Rocky Linux ve AlmaLinux

`KilimcininKoroglu/sshknockd` GitHub releases sayfasından son `.rpm` paketini indirin ve kurun:

```sh
sudo dnf install -y ipset iptables curl
sudo rpm -Uvh ./sshknockd-0.1.0-1.x86_64.rpm
```

`dnf` yoksa platformunuzun package manager’ını kullanın.

### Server’ı yapılandırma

Firewall erişimini açmadan önce kurulu config dosyasını düzenleyin:

```sh
sudo editor /etc/sshknockd.toml
```

Paketlenen config placeholder knock portları içerir ve siz bunları değiştirmeden başlamaz. Server’ınız için en az şu değerleri ayarlayın:

- `listen`: knock listener’ların kullanacağı adres.
- `ssh_port`: korunacak SSH server portu.
- `ipset_name`: geçici allowlist set’i.
- `ban_ipset_name`: rate-limit ban set’i.
- `invalid_burst_limit` ve `invalid_refill_per_minute`: rate-limit policy.
- `ban_timeout`: saniye cinsinden ban süresi.
- `knock.sequence`: deployment-specific protocol, port ve packet size sequence.

### Firewall kurallarını yapılandırma

`/etc/sshknockd.toml` düzenlendikten sonra setup komutunu bir kez çalıştırın:

```sh
sudo sshknockd --config /etc/sshknockd.toml setup-firewall
```

Paket kurulumu sırasında firewall kuralları değiştirilmez. `setup-firewall` komutu allow ipset oluşturur, ban ipset oluşturur, protected SSH port için allowlisted source’ları kabul eder, protected SSH port’a gelen diğer trafiği düşürür ve rate limit nedeniyle banlanan source’lardan gelen trafiği düşürür.

### Daemon’ı başlatma

systemd servisini enable edin ve başlatın:

```sh
sudo systemctl enable --now sshknockd
sudo systemctl status sshknockd
```

Audit log’ları izleyin:

```sh
sudo tail -f /var/log/sshknockd/sshknockd.log
```

Daemon, `log_file` içine SIEM odaklı audit event’leri yazar. `info` seviyesinde event’ler daemon startup, firewall preflight success veya failure, listener bind’ları, temporary SSH allow entries, rate-limit bans ve firewall command failures içerir. `debug` ve `trace` ayrıca source IP ile redacted observation ve outcome class içeren bounded packet observations ile knock outcomes kayıtlarını etkinleştirir. Knock protocol, knock port, packet size, sequence position ve full knock sequence loglanmaz.

### Update

Built-in GitHub repository’den update edin ve servisi restart edin:

```sh
sudo sshknockd update
```

Komut `KilimcininKoroglu/sshknockd` içindeki latest release’i kontrol eder, installed version ile karşılaştırır, Debian veya Ubuntu için `.deb`, CentOS, Fedora, RHEL, Rocky Linux veya AlmaLinux için `.rpm` package seçer, indirilen paketi GitHub release asset `sha256` digest değeriyle doğrular, `dpkg -i` veya `rpm -Uvh` ile kurar ve ardından `systemctl restart sshknockd` çalıştırır.

Release asset adları package extension ve architecture içermelidir. x86_64 Debian veya Ubuntu için `.deb` asset adı `amd64` içermelidir. x86_64 RPM tabanlı sistemler için `.rpm` asset adı `x86_64` içermelidir. ARM64 sistemler için asset adları `arm64` veya `aarch64` içermelidir.

## Clientless knock örnekleri

Her `<PORT*>` ve `<SIZE*>` değerini `/etc/sshknockd.toml` içindeki deployment-specific sequence ile değiştirin.

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
