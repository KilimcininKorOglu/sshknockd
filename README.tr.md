# sshknockd

[English](README.md)

[![Packages](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml/badge.svg)](https://github.com/KilimcininKoroglu/sshknockd/actions/workflows/packages.yml)
[![Son Release](https://img.shields.io/github/v/release/KilimcininKoroglu/sshknockd?sort=semver)](https://github.com/KilimcininKoroglu/sshknockd/releases/latest)
[![Release Downloads](https://img.shields.io/github/downloads/KilimcininKoroglu/sshknockd/total)](https://github.com/KilimcininKoroglu/sshknockd/releases)
[![License](https://img.shields.io/github/license/KilimcininKoroglu/sshknockd)](LICENSE)

`sshknockd`, SSH erişim kontrolü için hafif, sunucu tarafında çalışan bir port knocking daemon'udur. Korunan SSH portunu, kaynak IP yapılandırılmış knock dizisini gönderene kadar kapalı tutar; ardından o kaynağı `ipset` ve `iptables` üzerinden geçici olarak kabul eder. Böylece SSH portunun hedefsiz internet taramalarına ve otomatik kaba kuvvet trafiğine maruz kalması azalır.

## Özellikler

- Tasarım gereği istemcisiz. İstemciler knock dizisini `nc`, kabuk yönlendirmesi, `ping` veya SSH `ProxyCommand` gibi standart araçlarla üretir. Ayrı bir istemci çalıştırılabilir dosyası gerekmez.
- UDP, TCP ve ICMP üzerinden çok protokollü knock adımları; her biri tam bir yük boyutu gerektirir.
- Kaynak IP'ye bağlı dizi durumu; sınırlı bir zaman penceresi ve eşzamanlı kısmi durumlar için bir kapasite sınırıyla.
- Token bucket ile kaynak başına hız sınırlama. Kötüye kullanan kaynaklar, yapılandırılabilir bir süre boyunca yasak ipset'ine taşınır.
- `iptables` artı `ipset hash:ip` ve `ip6tables` artı `ipset hash:ip family inet6` üzerinden IPv4 ve IPv6 desteği.
- Knock dizisini ya da onu yeniden oluşturmaya yetecek ayrıntıyı asla kaydetmeyen, SIEM odaklı denetim günlüğü.
- Gömülü bir ed25519 anahtarıyla doğrulanan, imzalı GitHub sürüm paketlerinden kendini güncelleme.
- `amd64` ve `arm64` için Debian ve RPM paketleri olarak; bir `systemd` birimi ve `sshknockd(8)` man sayfasıyla dağıtılır.

## Nasıl çalışır

1. Daemon, yapılandırılmış dizideki her protokol ve port için dinleyicileri bağlar.
2. Bir kaynak IP, her knock adımını sırayla; doğru protokol, hedef port ve tam yük boyutuyla, `sequence_window` saniye içinde göndermelidir.
3. Tam eşleşmede kaynak IP, `ip_timeout` saniyelik bir zaman aşımıyla izin ipset'ine eklenir. Güvenlik duvarı bu süre boyunca o kaynağı korunan SSH portunda kabul eder.
4. Yanlış protokol, yanlış port, yanlış boyut veya zaman aşımı, o kaynak için kısmi dizi durumunu sıfırlar.
5. Geçersiz deneme hız sınırını aşan kaynaklar, `ban_timeout` saniye boyunca yasak ipset'i üzerinden yasaklanır.

Knock dizisi bir kimlik doğrulama değildir. Yakalanan bir dizi, uygun bir ağ yolundan yeniden gönderilebilir. Gerçek güvenlik sınırı SSH kimlik doğrulaması olarak kalır.

## Gereksinimler

- `iptables` (veya `ip6tables`), `ipset` ve `curl` bulunan bir Linux sistemi.
- Güvenlik duvarı kurallarını yönettiği için daemon'un root yetkisi.
- Korunan `ssh_port` üzerinde dinleyen OpenSSH veya Dropbear gibi bir SSH sunucusu. `sshknockd`, SSH'ı içermez veya değiştirmez; SSH sunucusunu ayrıca kurup yapılandırın.

## Kurulum

İşlemci mimarinize uygun paketi [sürümler sayfasından](https://github.com/KilimcininKoroglu/sshknockd/releases/latest) indirin. x86_64 için `amd64` (`.deb`) veya `x86_64` (`.rpm`), ARM64 için `arm64` (`.deb`) veya `aarch64` (`.rpm`) kullanın.

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

`dnf` yoksa dağıtımınızın paket yöneticisini kullanın. Paket kurulumu hiçbir güvenlik duvarı kuralını değiştirmez. Yalnızca çalıştırılabilir dosyayı, varsayılan `/etc/sshknockd.toml` dosyasını, `systemd` birimini ve man sayfasını kurar.

## Hızlı başlangıç

```sh
# 1. Yapılandırmayı düzenleyin ve yer tutucu knock portlarını değiştirin.
sudo editor /etc/sshknockd.toml

# 2. ipset'leri ve güvenlik duvarı kurallarını bir kez oluşturun.
sudo sshknockd --config /etc/sshknockd.toml setup-firewall

# 3. Daemon'ı etkinleştirin ve başlatın.
sudo systemctl enable --now sshknockd

# 4. Denetim günlüğünü izleyin.
sudo tail -f /var/log/sshknockd/sshknockd.log
```

Paketlenen yapılandırma, yer tutucu knock portları `0` olarak gelir ve siz bunları değiştirene kadar başlamaz.

## Yapılandırma

Örnek yapılandırma [sshknockd.toml](sshknockd.toml) dosyasıdır. Kurulu yol `/etc/sshknockd.toml` şeklindedir.

### Sunucu ayarları

| Ayar                        |                    Varsayılan örnek | Anlamı                                                                                 |
|-----------------------------|-----------------------------------:|----------------------------------------------------------------------------------------|
| `listen`                    |                          `0.0.0.0` | Knock dinleyicilerinin kullandığı yerel adres. IPv6 dinleyicileri için `::` kullanın.  |
| `ssh_port`                  |                            `10022` | Geçerli bir knock dizisinden sonra geçici olarak açılan SSH TCP portu.                 |
| `ipset_name`                |                        `ssh_allow` | Geçici olarak izin verilen kaynak IP adreslerini tutan ipset adı.                      |
| `firewall_backend`          |                         `iptables` | Güvenlik duvarı komut ailesi. IPv4 için `iptables`, IPv6 için `ip6tables`.             |
| `address_family`            |                             `ipv4` | ipset adres ailesi. Desteklenen değerler `ipv4` ve `ipv6`.                             |
| `sequence_window`           |                                `5` | İlk geçerli knock adımından son geçerli adıma kadar izin verilen azami saniye (1 - 60).|
| `ip_timeout`                |                               `10` | Başarılı knock yapan kaynak IP'nin ipset içinde izinli kalacağı saniye.                |
| `partial_state_timeout`     |                               `10` | Tamamlanmamış kaynak başına knock durumu silinmeden önce beklenecek saniye.            |
| `max_partial_states`        |                             `4096` | Eşzamanlı tamamlanmamış kaynak başına knock durumu üst sınırı.                         |
| `max_payload_size`          |                              `512` | Paket aşırı büyük sayılmadan önce kabul edilen azami knock yük boyutu.                 |
| `log_level`                 |                             `info` | Günlük ayrıntı düzeyi. `info` güvenlik durum değişikliklerini; `debug` ve `trace` sınırlı paket telemetrisi ekler. |
| `log_file`                  | `/var/log/sshknockd/sshknockd.log` | SIEM odaklı denetim günlüğü dosya yolu.                                                |
| `invalid_burst_limit`       |                               `20` | Yasaklama mantığı tetiklenmeden önce kaynak başına izin verilen geçersiz paket sayısı. |
| `invalid_refill_per_minute` |                               `10` | Kaynak başına her dakika geri yüklenen geçersiz paket hakkı.                           |
| `ban_timeout`               |                            `86400` | Hız sınırına takılan kaynak IP'nin yasak ipset'inde kalacağı saniye.                   |
| `ban_ipset_name`            |                    `sshknockd_ban` | Kaynak IP yasakları için kullanılan ipset adı.                                         |

### Knock dizisi

Dizi en az üç adım içermelidir. Her adım bir protokol ve tam bir yük boyutu gerektirir. TCP ve UDP adımları ayrıca bir hedef port gerektirir.

| Ayar                        |                Varsayılan örnek | Anlamı                                                               |
|-----------------------------|--------------------------------:|----------------------------------------------------------------------|
| `knock.sequence[].protocol` |                           `udp` | Adımın knock taşıması. Desteklenen değerler `udp`, `tcp` ve `icmp`.  |
| `knock.sequence[].port`     |          değiştirilene kadar `0` | `udp` ve `tcp` adımları için hedef port. `icmp` için belirtmeyin. `0` reddedilir. |
| `knock.sequence[].size`     |                    siteye özgü | Adım için gereken tam yük boyutu; 1 ile `max_payload_size` arasında. |

Daemon, yapılandırmayı başlangıçta doğrular ve bilinmeyen alanları reddeder; böylece bir yazım hatası güvenlik duruşunu sessizce değiştiremez. TCP ve UDP portları benzersiz olmalı ve `ssh_port` ile çakışmamalıdır. IPv4, `iptables` artı `ipset hash:ip` kullanır; IPv6, `ip6tables` artı `ipset hash:ip family inet6` kullanır.

## Güvenlik duvarı kurulumu

`/etc/sshknockd.toml` düzenlendikten sonra kurulum komutunu bir kez çalıştırın:

```sh
sudo sshknockd --config /etc/sshknockd.toml setup-firewall
```

Komut, izin ipset'ini oluşturur, yasak ipset'ini oluşturur, korunan SSH portunda eşleşen izin listesindeki kaynakları kabul eder, korunan SSH portuna gelen diğer trafiği düşürür ve hız sınırına takılan yasaklı kaynaklardan gelen trafiği düşürür. Güvenlik duvarı kuralları paket kurulumu sırasında değiştirilmez.

## Denetim günlüğü

Daemon, `log_file` içine SIEM odaklı denetim olayları yazar. `info` düzeyinde olaylar; daemon başlangıcını, güvenlik duvarı ön kontrolünün başarısını veya başarısızlığını, dinleyici bağlamalarını, geçici SSH izin kayıtlarını, hız sınırı yasaklarını ve güvenlik duvarı komut hatalarını içerir. `debug` ve `trace` düzeyleri; kaynak IP ile birlikte maskelenmiş gözlem ve sonuç sınıflarını içeren sınırlı paket gözlemleri ve knock sonuçları ekler. Günlükler asla knock protokolünü, knock portunu, paket boyutunu, dizi konumunu veya tam knock dizisini içermez.

## Güncelleme

```sh
sudo sshknockd update
```

Komut, `KilimcininKoroglu/sshknockd` deposundaki son sürümü kontrol eder, kurulu sürümle karşılaştırır ve Debian veya Ubuntu için `.deb`, CentOS/Fedora/RHEL/Rocky Linux/AlmaLinux için `.rpm` paketi seçer. Paket, sağlama toplamı ve imza indirmelerini yönlendirmeler dahil yalnızca HTTPS ile sınırlar, imzalı `SHA256SUMS` bildirimini gömülü bir ed25519 açık anahtarıyla doğrular, indirilen paketi bildirimdeki `sha256` özetiyle doğrular, `dpkg -i` veya `rpm -Uvh` ile kurar ve ardından `systemctl restart sshknockd` çalıştırır. İndirmeler, sürece özel yalnızca root erişimli geçici bir dizinde tutulur ve kurulumdan sonra ya da hata durumunda silinir.

Sürüm dosyası adları paket uzantısını ve mimariyi içermelidir. x86_64 Debian veya Ubuntu, `amd64` içeren bir `.deb` dosyası yayımlar; x86_64 RPM tabanlı sistemler `x86_64` içeren bir `.rpm` dosyası yayımlar. ARM64 sistemler `arm64` veya `aarch64` içeren dosyalar yayımlar.

## İstemcisiz knock örnekleri

Her `<PORT*>` ve `<SIZE*>` değerini `/etc/sshknockd.toml` içindeki dağıtıma özgü diziyle değiştirin.

```sh
printf '%0<SIZE1>s' '' | tr ' ' A | nc -u -w1 server.example.com <PORT1>
printf '%0<SIZE2>s' '' | tr ' ' B | nc -u -w1 server.example.com <PORT2>
printf '%0<SIZE3>s' '' | tr ' ' C | nc -u -w1 server.example.com <PORT3>
ssh -p 10022 user@server.example.com
```

Aynı dizi bir SSH `ProxyCommand` olarak da çalışır; böylece `ssh` bağlanmadan önce knock'u otomatik gönderir:

```sshconfig
Host protected-server
    HostName server.example.com
    Port 10022
    User user
    ProxyCommand sh -c 'printf "%0<SIZE1>s" "" | tr " " A | nc -u -w1 %h <PORT1>; printf "%0<SIZE2>s" "" | tr " " B | nc -u -w1 %h <PORT2>; printf "%0<SIZE3>s" "" | tr " " C | nc -u -w1 %h <PORT3>; sleep 1; nc %h %p'
```

## Kaynaktan derleme

```sh
cargo build --release --locked
cargo test --all-targets --locked
```

Yerel paketleri derleyin:

```sh
cargo install cargo-deb --version 3.7.0
cargo install cargo-generate-rpm --version 0.18.0 --locked
cargo build --release --locked
cargo deb --no-build
cargo generate-rpm
```

Paketler `amd64` ve `arm64` için derlenir ve `sshknockd(8)` man sayfasını içerir. Bir paket kurulduktan sonra, daemon ve yönetim komutu referansı için `man sshknockd` çalıştırın. Paket adı değiştirildikten sonra paketleri yeniden derlemeden önce eski dosyaları kaldırın veya `cargo clean` çalıştırın.

## Komutlar

| Komut | Amaç |
|---|---|
| `sshknockd --config <yol>` | Verilen yapılandırmayla daemon'ı başlatır. |
| `sshknockd --config <yol> setup-firewall` | Korunan SSH portu için ipset'leri ve güvenlik duvarı kurallarını oluşturur. |
| `sshknockd --config <yol> config` | Yüklenen yapılandırmanın kısa bir özetini yazdırır. |
| `sshknockd update` | Son sürüm paketini indirir, doğrular, kurar ve etkinleştirir. |
| `sshknockd version` | Kurulu sürümü yazdırır. |

## Güvenlik notları

- Knock dizisi bir gizlemedir, kimlik doğrulama değildir. SSH kimlik doğrulamasını güçlü tutun.
- Daemon, güvenlik duvarını yönetmek için root olarak çalışır. Paketlenen `systemd` birimi; `NoNewPrivileges`, `ProtectHome`, `PrivateTmp` ve `MemoryDenyWriteExecute` gibi sıkılaştırma seçeneklerini uygular.
- Güvenlik duvarı komutları açık argümanlarla ve asla bir kabuk üzerinden çalıştırılmaz; bu yüzden yapılandırma değerleri komut enjekte edemez.

## Lisans

[Apache License 2.0](LICENSE) altında lisanslanmıştır.

