# sshknockd

[English](README.md)

[![Packages](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml/badge.svg)](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml)
[![Son Release](https://img.shields.io/github/v/release/KilimcininKoroglu/sshknockd?sort=semver)](https://github.com/KilimcininKoroglu/sshknockd/releases/latest)
[![Release Downloads](https://img.shields.io/github/downloads/KilimcininKoroglu/sshknockd/total)](https://github.com/KilimcininKoroglu/sshknockd/releases)
[![License](https://img.shields.io/github/license/KilimcininKoroglu/sshknockd)](LICENSE)

`sshknockd`, SSH erişim kontrolü için hafif bir server-side port knocking daemon'udur. Kaynak IP yapılandırılmış bir knock sequence göndermeden korunan SSH portunu kapalı tutar, ardından o kaynağı `ipset` ve `iptables` üzerinden geçici olarak kabul eder. Daemon, SSH portunun hedefsiz internet taramalarına ve otomatik brute-force trafiğine maruziyetini azaltır.

## Özellikler

- Tasarım gereği clientless. İstemciler knock sequence'i `nc`, shell redirection, `ping` veya SSH `ProxyCommand` gibi standart araçlarla üretir. Ayrı bir client binary gerekmez.
- UDP, TCP ve ICMP üzerinden çok protokollü knock step'leri, her biri gerekli tam payload size ile.
- Kaynak IP'ye bağlı sequence state, sınırlı zaman penceresi ve eşzamanlı partial state'ler için kapasite sınırı ile.
- Token bucket ile kaynak başına rate limiting. Kötüye kullanan kaynaklar yapılandırılabilir bir süre için ban `ipset`'ine taşınır.
- `iptables` artı `ipset hash:ip` ve `ip6tables` artı `ipset hash:ip family inet6` üzerinden IPv4 ve IPv6 desteği.
- Knock sequence'i veya onu yeniden oluşturmaya yetecek ayrıntıyı asla kaydetmeyen SIEM odaklı audit logging.
- Gömülü bir ed25519 anahtarıyla doğrulanan, imzalı GitHub release paketlerinden kendini güncelleme.
- `amd64` ve `arm64` için Debian ve RPM paketleri olarak, bir `systemd` unit ve `sshknockd(8)` man sayfası ile dağıtılır.

## Nasıl çalışır

1. Daemon, yapılandırılmış sequence'teki her protokol ve port için listener'ları bağlar.
2. Bir kaynak IP her knock step'ini sırayla, doğru protokol, hedef port ve tam payload size ile, `sequence_window` saniye içinde göndermelidir.
3. Tam eşleşmede kaynak IP, `ip_timeout` saniyelik bir timeout ile allow `ipset`'ine eklenir. Firewall bu süre boyunca o kaynağı korunan SSH portunda kabul eder.
4. Yanlış protokol, yanlış port, yanlış size veya timeout, o kaynak için partial sequence state'i sıfırlar.
5. Invalid deneme rate limit'ini aşan kaynaklar, `ban_timeout` saniye için ban `ipset`'i üzerinden banlanır.

Knock sequence bir authentication değildir. Yakalanan bir sequence, uygun bir ağ yolundan yeniden gönderilebilir. Gerçek güvenlik sınırı SSH authentication olarak kalır.

## Gereksinimler

- `iptables` (veya `ip6tables`), `ipset` ve `curl` bulunan bir Linux sistemi.
- Firewall kurallarını yönettiği için daemon'un root yetkisi.
- Korunan `ssh_port` üzerinde dinleyen OpenSSH veya Dropbear gibi bir SSH server. `sshknockd`, SSH'ı gömmez veya değiştirmez; SSH server'ı ayrıca kurun ve yapılandırın.

## Kurulum

CPU architecture'ınıza uygun paketi [releases sayfasından](https://github.com/KilimcininKoroglu/sshknockd/releases/latest) indirin. x86_64 için `amd64` (`.deb`) veya `x86_64` (`.rpm`), ARM64 için `arm64` (`.deb`) veya `aarch64` (`.rpm`) kullanın.

### Debian ve Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y ipset iptables curl
sudo dpkg -i ./sshknockd_<sürüm>_amd64.deb
```

### CentOS, Fedora, RHEL, Rocky Linux ve AlmaLinux

```sh
sudo dnf install -y ipset iptables curl
sudo rpm -Uvh ./sshknockd-<sürüm>.x86_64.rpm
```

`dnf` yoksa platformunuzun package manager'ını kullanın. Paket kurulumu hiçbir firewall kuralını değiştirmez. Binary'yi, varsayılan `/etc/sshknockd.toml` dosyasını, `systemd` unit'ini ve man sayfasını kurar.

## Hızlı başlangıç

```sh
# 1. Yapılandırmayı düzenleyin ve placeholder knock portlarını değiştirin.
sudo editor /etc/sshknockd.toml

# 2. ipset'leri ve firewall kurallarını bir kez oluşturun.
sudo sshknockd --config /etc/sshknockd.toml setup-firewall

# 3. Daemon'ı enable edin ve başlatın.
sudo systemctl enable --now sshknockd

# 4. Audit log'u izleyin.
sudo tail -f /var/log/sshknockd/sshknockd.log
```

Paketlenen yapılandırma, placeholder knock portları `0` olarak gelir ve siz bunları değiştirene kadar başlamaz.

## Yapılandırma

Örnek yapılandırma [sshknockd.toml](sshknockd.toml) dosyasıdır. Kurulu yol `/etc/sshknockd.toml` şeklindedir.

### Server ayarları

| Ayar                        |                   Varsayılan örnek | Anlamı                                                                                 |
|-----------------------------|-----------------------------------:|----------------------------------------------------------------------------------------|
| `listen`                    |                          `0.0.0.0` | Knock listener'ların kullandığı yerel adres. IPv6 listener için `::` kullanın.         |
| `ssh_port`                  |                            `10022` | Geçerli knock sequence sonrasında geçici olarak açılan SSH TCP portu.                  |
| `ipset_name`                |                        `ssh_allow` | Geçici izin verilen source IP adreslerini tutan ipset adı.                             |
| `firewall_backend`          |                         `iptables` | Firewall komut ailesi. IPv4 için `iptables`, IPv6 için `ip6tables`.                    |
| `address_family`            |                             `ipv4` | ipset address family. Desteklenen değerler `ipv4` ve `ipv6`.                           |
| `sequence_window`           |                                `5` | İlk geçerli knock step ile son geçerli step arasında izin verilen maksimum saniye (1 ile 60). |
| `ip_timeout`                |                               `10` | Başarılı knock yapan source IP adresinin ipset içinde izinli kalacağı saniye.          |
| `partial_state_timeout`     |                               `10` | Eksik per-source knock state temizlenmeden önce beklenecek saniye.                     |
| `max_partial_states`        |                             `4096` | Eşzamanlı eksik per-source knock state üst sınırı.                                     |
| `max_payload_size`          |                              `512` | Packet oversized sayılmadan önce kabul edilen maksimum knock payload size.             |
| `log_level`                 |                             `info` | Audit verbosity. `info` security state change'leri loglar; `debug` ve `trace` bounded packet telemetry ekler. |
| `log_file`                  | `/var/log/sshknockd/sshknockd.log` | SIEM odaklı audit log dosya yolu.                                                      |
| `invalid_burst_limit`       |                               `20` | Ban mantığı tetiklenmeden önce source başına izin verilen invalid packet burst değeri. |
| `invalid_refill_per_minute` |                               `10` | Source başına her dakika geri eklenen invalid packet hakkı.                            |
| `ban_timeout`               |                            `86400` | Rate limit'e takılan source IP'nin ban ipset içinde kalacağı saniye.                   |
| `ban_ipset_name`            |                    `sshknockd_ban` | Source IP ban'leri için kullanılan ipset adı.                                          |

### Knock sequence

Sequence en az üç step içermelidir. Her step bir protokol ve tam bir payload size gerektirir. TCP ve UDP step'leri ayrıca bir hedef port gerektirir.

| Ayar                        |             Varsayılan örnek | Anlamı                                                               |
|-----------------------------|-----------------------------:|----------------------------------------------------------------------|
| `knock.sequence[].protocol` |                        `udp` | Step için knock transport. Desteklenen değerler `udp`, `tcp` ve `icmp`. |
| `knock.sequence[].port`     |         değiştirilene kadar `0` | `udp` ve `tcp` step'leri için hedef port. `icmp` için belirtmeyin. `0` reddedilir. |
| `knock.sequence[].size`     |                site-specific | Step için gereken tam payload size, 1 ile `max_payload_size` arasında. |

Daemon yapılandırmayı başlangıçta doğrular ve bilinmeyen alanları reddeder, böylece bir yazım hatası güvenlik duruşunu sessizce değiştiremez. TCP ve UDP portları benzersiz olmalı ve `ssh_port` ile çakışmamalıdır. IPv4, `iptables` artı `ipset hash:ip` kullanır; IPv6, `ip6tables` artı `ipset hash:ip family inet6` kullanır.

## Firewall kurulumu

`/etc/sshknockd.toml` düzenlendikten sonra setup komutunu bir kez çalıştırın:

```sh
sudo sshknockd --config /etc/sshknockd.toml setup-firewall
```

Komut allow ipset'i oluşturur, ban ipset'i oluşturur, korunan SSH portunda eşleşen allowlisted kaynakları kabul eder, korunan SSH portuna gelen diğer trafiği düşürür ve rate limit'e takılan banlı kaynaklardan gelen trafiği düşürür. Firewall kuralları paket kurulumu sırasında değiştirilmez.

## Audit logging

Daemon, `log_file` içine SIEM odaklı audit event'leri yazar. `info` seviyesinde event'ler daemon startup, firewall preflight success veya failure, listener bind'ları, geçici SSH allow kayıtları, rate-limit ban'leri ve firewall command failures içerir. `debug` ve `trace`, source IP ile redacted observation ve outcome class içeren bounded packet observations ve knock outcomes ekler. Log'lar asla knock protokolünü, knock portunu, packet size'ı, sequence pozisyonunu veya tam knock sequence'i içermez.

## Güncelleme

```sh
sudo sshknockd update
```

Komut, `KilimcininKoroglu/sshknockd` içindeki son release'i kontrol eder, kurulu sürümle karşılaştırır ve Debian veya Ubuntu için `.deb`, CentOS, Fedora, RHEL, Rocky Linux veya AlmaLinux için `.rpm` paketi seçer. Package, checksum ve signature indirmelerini redirect'ler dahil yalnızca HTTPS ile sınırlar, imzalı `SHA256SUMS` manifest'ini gömülü bir ed25519 public key ile doğrular, indirilen paketi manifest `sha256` digest değeriyle doğrular, `dpkg -i` veya `rpm -Uvh` ile kurar ve ardından `systemctl restart sshknockd` çalıştırır.

Release asset adları package extension ve architecture içermelidir. x86_64 Debian veya Ubuntu, `amd64` içeren bir `.deb` asset yayınlar; x86_64 RPM tabanlı sistemler `x86_64` içeren bir `.rpm` asset yayınlar. ARM64 sistemler `arm64` veya `aarch64` içeren asset'ler yayınlar.

## Clientless knock örnekleri

Her `<PORT*>` ve `<SIZE*>` değerini `/etc/sshknockd.toml` içindeki deployment-specific sequence ile değiştirin.

```sh
printf '%0<SIZE1>s' '' | tr ' ' A | nc -u -w1 server.example.com <PORT1>
printf '%0<SIZE2>s' '' | tr ' ' B | nc -u -w1 server.example.com <PORT2>
printf '%0<SIZE3>s' '' | tr ' ' C | nc -u -w1 server.example.com <PORT3>
ssh -p 10022 user@server.example.com
```

Aynı sequence bir SSH `ProxyCommand` olarak da çalışır, böylece `ssh` bağlanmadan önce knock'u otomatik gönderir:

```sshconfig
Host protected-server
    HostName server.example.com
    Port 10022
    User user
    ProxyCommand sh -c 'printf "%0<SIZE1>s" "" | tr " " A | nc -u -w1 %h <PORT1>; printf "%0<SIZE2>s" "" | tr " " B | nc -u -w1 %h <PORT2>; printf "%0<SIZE3>s" "" | tr " " C | nc -u -w1 %h <PORT3>; sleep 1; nc %h %p'
```

## Kaynaktan build

```sh
cargo build --release --locked
cargo test --all-targets --locked
```

Local paketleri build edin:

```sh
cargo install cargo-deb --version 3.7.0
cargo install cargo-generate-rpm --version 0.18.0 --locked
cargo build --release --locked
cargo deb --no-build
cargo generate-rpm
```

Paketler `amd64` ve `arm64` için build edilir ve `sshknockd(8)` man sayfasını içerir. Paket kurulduktan sonra daemon ve administrative command reference için `man sshknockd` çalıştırın. Package adı değiştikten sonra paketleri yeniden build etmeden önce stale artifact'leri kaldırın veya `cargo clean` çalıştırın.

## Komutlar

| Komut | Amaç |
|---|---|
| `sshknockd --config <yol>` | Verilen yapılandırma ile daemon'ı başlatır. |
| `sshknockd --config <yol> setup-firewall` | Korunan SSH portu için ipset'leri ve firewall kurallarını oluşturur. |
| `sshknockd --config <yol> config` | Yüklenen yapılandırmanın kısa özetini yazdırır. |
| `sshknockd update` | Son release paketini indirir, doğrular, kurar ve etkinleştirir. |
| `sshknockd version` | Kurulu sürümü yazdırır. |

## Güvenlik notları

- Knock sequence obfuscation'dır, authentication değildir. SSH authentication'ı güçlü tutun.
- Daemon, firewall'ı yönetmek için root olarak çalışır. Paketlenen `systemd` unit'i `NoNewPrivileges`, `ProtectHome`, `PrivateTmp` ve `MemoryDenyWriteExecute` gibi hardening seçeneklerini uygular.
- Firewall komutları açık argümanlarla ve asla bir shell üzerinden çalıştırılmaz, bu yüzden yapılandırma değerleri komut enjekte edemez.

## Lisans

[Apache License 2.0](LICENSE) altında lisanslanmıştır.

