# Packet Broker — Admin & Developer Guide

Kapsamli yonetim, konfigürasyon, lisanslama ve gelistirici kilavuzu.

---

## Icindekiler

1. [Kurulum & Derleme](#1-kurulum--derleme)
2. [Ilk Calistirma](#2-ilk-calistirma)
3. [Systemd ile Production Deployment](#3-systemd-ile-production-deployment)
4. [Kullanici Yonetimi & Roller](#4-kullanici-yonetimi--roller)
5. [Iki Faktorlu Dogrulama (2FA/TOTP)](#5-iki-faktorlu-dogrulama-2fatotp)
6. [Lisans Sistemi](#6-lisans-sistemi)
7. [Kural Yonetimi](#7-kural-yonetimi)
8. [VLAN Manipulasyonu](#8-vlan-manipulasyonu)
9. [Paket Filtreleme (Genisletilmis)](#9-paket-filtreleme-genisletilmis)
10. [Traffic Mirroring (SPAN)](#10-traffic-mirroring-span)
11. [Load Balancing](#11-load-balancing)
12. [Bandwidth Throttling](#12-bandwidth-throttling)
13. [Packet Deduplication](#13-packet-deduplication)
14. [SSL/TLS Inspection](#14-ssltls-inspection)
15. [PCAP Capture](#15-pcap-capture)
16. [Alert & Monitoring](#16-alert--monitoring)
17. [Health Checks](#17-health-checks)
18. [Syslog / SIEM Entegrasyonu](#18-syslog--siem-entegrasyonu)
19. [Cluster Mode](#19-cluster-mode)
20. [Backup & Restore](#20-backup--restore)
21. [Firmware Update](#21-firmware-update)
22. [Audit Log](#22-audit-log)
23. [Log Rotation](#23-log-rotation)
24. [Tema (Dark/Light)](#24-tema-darklight)
25. [JSON API Referansi](#25-json-api-referansi)
26. [Konfigürasyon Dosyalari](#26-konfigürasyon-dosyalari)
27. [C Binary Teknik Detay](#27-c-binary-teknik-detay)
28. [Guvenlik Notlari](#28-guvenlik-notlari)
29. [Troubleshooting](#29-troubleshooting)
30. [Gelistirici Referansi](#30-gelistirici-referansi)

---

## 1. Kurulum & Derleme

### Gereksinimler

- Go 1.22+ (web UI icin)
- GCC + libpcap-dev (C binary icin)
- Linux (production, /proc/net/dev ve /sys/class/net erisimi icin)
- macOS desteklenir (gelistirme, netstats/sysinfo degrade olur)

### Go Web UI Derleme

```bash
# Standart build
go build -o packet_broker_ui .

# ARM64 cross-compile (embedded donanim icin)
GOOS=linux GOARCH=arm64 go build -o packet_broker_ui .

# ARM32 (Raspberry Pi vb.)
GOOS=linux GOARCH=arm GOARM=7 go build -o packet_broker_ui .
```

### C Binary Derleme (libpcap)

```bash
# x86_64 Linux
gcc -O2 -o packet_broker c_src/packet_broker_libpcap.c -lpcap -lpthread

# ARM64 cross-compile
aarch64-linux-gnu-gcc -O2 -o packet_broker c_src/packet_broker_libpcap.c -lpcap -lpthread
```

### C Binary Derleme (DPDK)

```bash
gcc -O2 -o packet_broker c_src/packet_broker.c $(pkg-config --cflags --libs libdpdk) -lpthread

# Calistirma (root ve hugepages gerekli)
sudo ./packet_broker -l 0-3 -n 4 --
```

---

## 2. Ilk Calistirma

```bash
# Calisma dizininde su dosyalar olmali:
# - packet_broker_ui    (Go binary)
# - packet_broker       (C binary)
# - templates/          (HTML template klasoru)

./packet_broker_ui
```

**Varsayilan ayarlar:**
- Web UI: `http://localhost:8005`
- Varsayilan kullanici: `admin` / `admin`
- Otomatik olusturulan dosyalar:
  - `users.db` — SQLite veritabani (kullanicilar, alertler, backuplar vs.)
  - `packet_broker.log` — Uygulama logu
  - `packet_broker.status` — Broker durumu ("running"/"stopped")
  - `rules.conf` — C binary icin kural dosyasi
  - `rules_state.json` — Tam kural state'i (JSON)

> **UYARI:** Ilk giriste `admin/admin` sifresini degistirin! Dashboard'da sari uyari gorunecektir.

---

## 3. Systemd ile Production Deployment

### Dosya Yerlesimi

```bash
# Hedef dizin olustur
sudo mkdir -p /opt/packet-broker
sudo cp packet_broker_ui packet_broker /opt/packet-broker/
sudo cp -r templates/ /opt/packet-broker/

# Systemd service yukle
sudo cp deploy/packet-broker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable packet-broker
sudo systemctl start packet-broker
```

### Service Durumu

```bash
sudo systemctl status packet-broker
sudo journalctl -u packet-broker -f        # canli log
sudo systemctl restart packet-broker       # yeniden baslatma
```

### Service Konfigürasyonu

Dosya: `/etc/systemd/system/packet-broker.service`

| Parametre | Deger | Aciklama |
|---|---|---|
| `WorkingDirectory` | `/opt/packet-broker` | Calisma dizini |
| `Restart` | `always` | Her crash'te otomatik yeniden baslat |
| `RestartSec` | `5` | 5 saniye bekleme |
| `LimitNOFILE` | `65536` | Dosya descriptor limiti |
| `GOMAXPROCS` | `4` | Go thread sayisi |
| `ProtectSystem` | `strict` | Sadece ReadWritePaths yazilabilir |
| `NoNewPrivileges` | `true` | Privilege escalation engellenir |

---

## 4. Kullanici Yonetimi & Roller

### Roller

| Rol | Yetkiler |
|---|---|
| `admin` | Tum islemler: kural ekleme/silme, kullanici yonetimi, sistem ayarlari |
| `user` | Salt okunur: dashboard, kurallar (silme/ekleme yok), operasyonel loglar |

### Kullanici Islemleri (Web UI → Users)

- **Ekleme:** Kullanici adi, sifre (min 8 karakter), rol secimi
- **Sifre degistirme:** Admin herhangi bir kullanicinin sifresini degistirebilir
- **Silme:** Son admin hesabi silinemez, admin kendini silemez

### Session & Guvenlik

| Parametre | Deger |
|---|---|
| Session suresi | 24 saat |
| Cookie | `HttpOnly`, `SameSite=Strict` |
| Sifre hashleme | bcrypt, cost=12 |
| Login rate limit | 5 deneme/dakika/IP |
| CSRF korumasi | Session-based token, constant-time karsilastirma |
| Zamanlama saldirisi | Mevcut olmayan kullanicilarda da bcrypt calistirilir |

---

## 5. Iki Faktorlu Dogrulama (2FA/TOTP)

### Etkinlestirme

1. **Profile** sayfasina git
2. "Two-Factor Authentication" bolumunde gizli anahtari gör
3. Google Authenticator veya Authy uygulamasina ekle
4. Uygulamadaki 6 haneli kodu gir ve **Verify & Enable** tikla

### Teknik Detaylar

| Parametre | Deger |
|---|---|
| Algoritma | HMAC-SHA1 (RFC 6238) |
| Kod uzunlugu | 6 hane |
| Periyot | 30 saniye |
| Tolerans | ±1 adim (±30 saniye) |
| Gizli anahtar | 160-bit, Base32 kodlu |

### QR URI Formati

```
otpauth://totp/PacketBroker:username?secret=BASE32SECRET&issuer=PacketBroker&digits=6&period=30
```

### Devre Disi Birakma

Profile → Two-Factor Authentication → **Disable 2FA**

---

## 6. Lisans Sistemi

### Genel Bakis

Lisans sistemi Ed25519 dijital imza tabanlidir. Her cihazin benzersiz bir Hardware ID'si vardir. Lisans bu ID'ye kilitlenir.

### Adim 1: Vendor Anahtar Cifti Olusturma (BIR KERE)

```bash
go run cmd/keygen/main.go -generate-keys
```

Cikti:
```
=== Ed25519 Key Pair ===

PUBLIC KEY (embed in license.go vendorPubKeyHex):
a1b2c3d4e5f6...  (64 hex karakter)

PRIVATE KEY (keep SECRET, use for signing):
f6e5d4c3b2a1...  (128 hex karakter)
```

> **KRITIK:** Private key'i guvenli bir yerde saklayin. Public key'i `internal/license/license.go` dosyasindaki `vendorPubKeyHex` degiskenine yapisitirin ve yeniden derleyin.

### Adim 2: Public Key'i Binary'ye Gomme

Dosya: `internal/license/license.go`, satir ~67:

```go
var vendorPubKeyHex = "a1b2c3d4e5f6..."  // 64 hex karakter
```

Degistirdikten sonra yeniden derleyin:
```bash
go build -o packet_broker_ui .
```

### Adim 3: Musteri Hardware ID'sini Alma

Musterinin cihazinda:
```bash
./packet_broker_ui  # baslatip web UI'dan System → License sayfasina bakin
# veya
go run cmd/keygen/main.go -hwid
```

Hardware ID ornegi: `a7f3c92b1d4e8f0612345678abcdef90` (32 hex karakter)

### Adim 4: Lisans Olusturma

```bash
go run cmd/keygen/main.go -sign \
  -privkey "f6e5d4c3b2a1...128_hex_chars" \
  -hardware-id "a7f3c92b1d4e8f0612345678abcdef90" \
  -customer "ACME Corp" \
  -type enterprise \
  -features "all" \
  -ports 24 \
  -expiry "2027-01-01" \
  -out license.key
```

### Lisans Parametreleri

| Parametre | Aciklama | Ornekler |
|---|---|---|
| `-privkey` | Vendor private key (128 hex) | Zorunlu |
| `-hardware-id` | Hedef cihaz HWID (32 hex) | Bos birak = tum cihazlar |
| `-customer` | Musteri adi | "ACME Corp" |
| `-type` | Lisans tipi | `trial`, `standard`, `enterprise` |
| `-features` | Ozellik listesi (virgul ayrimli) | `all` veya `mirror,ssl,cluster,dedup,throttle` |
| `-ports` | Maksimum port sayisi | `24`, `48`, `0` (sinirdiz) |
| `-expiry` | Son kullanma tarihi | `2027-01-01` veya `perpetual` |
| `-out` | Cikti dosya yolu | `license.key` |

### Adim 5: Lisansi Yukleme

1. Web UI → System → **License** sayfasi
2. **Upload & Activate** ile `license.key` dosyasini yukle
3. Lisans durumu ve detaylari gorunecektir

### Ornek Lisanslar

```bash
# Trial (30 gun, sinirli ozellikler)
go run cmd/keygen/main.go -sign \
  -privkey "$PRIVKEY" \
  -hardware-id "$HWID" \
  -customer "Demo User" \
  -type trial \
  -features "mirror,throttle" \
  -ports 8 \
  -expiry "2026-04-28"

# Enterprise (sinirsiz, tum ozellikler, perpetual)
go run cmd/keygen/main.go -sign \
  -privkey "$PRIVKEY" \
  -customer "BigCorp Inc" \
  -type enterprise \
  -features "all" \
  -expiry "perpetual"

# Hardware-locked standard
go run cmd/keygen/main.go -sign \
  -privkey "$PRIVKEY" \
  -hardware-id "a7f3c92b1d4e8f0612345678abcdef90" \
  -customer "SmallCo" \
  -type standard \
  -features "mirror,ssl,throttle" \
  -ports 24 \
  -expiry "2026-12-31"
```

### Hardware ID Nasil Hesaplaniyor?

Sirayla su kaynaklardan SHA256 hash alinir:
1. Tum MAC adresleri (sirali, loopback haric)
2. `/etc/machine-id` veya `/var/lib/dbus/machine-id`
3. `/sys/class/dmi/id/product_serial` (OEM metni haric)
4. Fallback: hostname + CPU mimarisi + OS

Sonuc: ilk 16 byte → 32 hex karakter

### Lisans Dosya Formati

```json
{
  "payload": "base64_encoded_json...",
  "signature": "base64_encoded_ed25519_signature..."
}
```

Payload decode edildiginde:
```json
{
  "hardware_id": "a7f3c92b...",
  "customer": "ACME Corp",
  "expiry": "2027-01-01",
  "features": ["all"],
  "max_ports": 24,
  "type": "enterprise",
  "issued_at": "2026-03-29"
}
```

---

## 7. Kural Yonetimi

### Kural Ekleme Yontemleri

1. **Topology Drag-and-Drop:** Sol porttan sag porta surukle-birak
2. **Manual Modal:** Rules sayfasinda "Manual" butonu
3. **JSON API:** `POST /add-rule` (form data)

### Kural Alanlari (22 alan)

| # | Alan | Tip | Varsayilan | Aciklama |
|---|---|---|---|---|
| 1 | `interface_in` | string | - | Giris interface'i (eth0, eth1...) |
| 2 | `tcp_flags` | string | "0" | TCP bayraklari: S(YN), A(CK), F(IN), R(ST), P(USH), U(RG) |
| 3 | `dest_port` | string | "0" | Hedef port (0 = hepsi) |
| 4 | `protocol` | string | "0" | TCP, UDP, ICMP (0 = hepsi) |
| 5 | `vlan_id` | string | "0" | VLAN ID filtresi (0 = hepsi) |
| 6 | `string_match` | string | "0" | Payload'da string arama |
| 7 | `exclude` | string | "0" | "1" = eslesen paketleri HARIC tut |
| 8 | `interface_out` | string | - | Cikis interface'i |
| 9 | `enabled` | bool | true | Kural aktif mi |
| 10 | `priority` | int | auto | Oncelik (0 = en yuksek) |
| 11 | `vlan_action` | string | "none" | none, add, remove, change |
| 12 | `vlan_new_id` | string | "0" | Hedef VLAN ID (add/change icin) |
| 13 | `truncate` | string | "0" | Paket kesme (byte), 0 = tam |
| 14 | `src_ip` | string | "0" | Kaynak IP (CIDR: 192.168.1.0/24) |
| 15 | `dst_ip` | string | "0" | Hedef IP (CIDR) |
| 16 | `src_mac` | string | "0" | Kaynak MAC (AA:BB:CC:DD:EE:FF) |
| 17 | `dst_mac` | string | "0" | Hedef MAC |
| 18 | `bpf_filter` | string | "" | BPF filtre ifadesi |
| 19 | `rate_limit_mbps` | string | "0" | Bant genisligi limiti (Mbps) |
| 20 | `rate_limit_pps` | string | "0" | Paket hizi limiti (pps) |
| 21 | `mirror_ports` | string | "" | Ek cikis portlari (virgul ayrimli) |
| 22 | `dedup_key` | string | "0" | Dedup grubu anahtari |

### Kural Siralama

- Kurallar oncelik sirasina gore islenilir (Priority alani)
- Web UI'da drag-and-drop ile siralama yapilabilir
- `POST /rules/reorder` JSON body: `{"order":[2,0,1,3]}`

### Kural Enable/Disable

- Her kural aktif/pasif yapilabilir
- Pasif kurallar `rules.conf`'a yazilmaz (C binary gormez)
- `POST /rules/{index}/toggle` ile degistirilir

### Dosya Yapisi

```
rules_state.json  ← Kaynak (JSON, tum alanlar, disabled dahil)
       ↓ writeCSV()
rules.conf        ← Turetilmis (22 alan CSV, sadece enabled kurallar)
       ↓ C binary okur
packet_broker     ← Paket isleme
```

---

## 8. VLAN Manipulasyonu

| Aksiyon | Aciklama | Paket Degisimi |
|---|---|---|
| `none` | Degisiklik yok | — |
| `add` | VLAN tag ekle | 4 byte 802.1Q header eklenir |
| `remove` | VLAN tag cikar | 4 byte 802.1Q header silinir |
| `change` | VLAN ID degistir | TCI alanindaki VID degisir, priority korunur |

**802.1Q Frame yapisi:**
```
[Dst MAC 6B][Src MAC 6B][0x8100 2B][TCI 2B][EtherType 2B][Payload...]
                                     ↑
                              Priority(3) + VID(12)
```

---

## 9. Paket Filtreleme (Genisletilmis)

### IP Filtresi (CIDR destekli)
```
src_ip = 192.168.1.0/24    # 192.168.1.0 - 192.168.1.255 arasi
dst_ip = 10.0.0.1           # tek IP (/32 varsayilan)
```

### MAC Filtresi
```
src_mac = AA:BB:CC:DD:EE:FF
dst_mac = 00:11:22:33:44:55
```

### TCP Bayrak Kombinasyonlari
```
S     = SYN (baglanti baslangici)
SA    = SYN+ACK (baglanti kabulu)
A     = ACK
F     = FIN (baglanti kapanisi)
R     = RST (sifirlama)
P     = PSH (veri itme)
```

### Paket Truncation Onerilen Degerler
```
64    = Sadece Ethernet + IP header
128   = Header + bazi TCP/UDP bilgisi
256   = Cogu header icin yeterli
0     = Tam paket (varsayilan)
```

---

## 10. Traffic Mirroring (SPAN)

Tek bir giris portundan gelen tum trafigi N hedef porta kopyalar.

**Olusturma:** Network → Mirror / SPAN
- **Kaynak port:** Trafigi dinlenecek interface
- **Hedef portlar:** Virgul ayrimli cikis portlari

**Ornek:** `eth0` → `eth12, eth13, eth14` (3 tool'a kopyala)

Her src→dst cifti icin otomatik olarak bir kural olusturulur (filtre yok = tum trafik).

---

## 11. Load Balancing

| Mod | Aciklama |
|---|---|
| Round-Robin | Paketler sirayla dagilir |
| Hash | Kaynak/hedef IP hash'ine gore dagitilir |

**Olusturma:** Network → Load Balance
- Grup adi, mod, giris portlari, cikis portlari

---

## 12. Bandwidth Throttling

Token bucket algoritmasiyla per-rule rate limiting.

| Parametre | Aciklama |
|---|---|
| Max Mbps | Bant genisligi siniri (0 = limitsiz) |
| Max PPS | Paket/saniye siniri (0 = limitsiz) |
| Burst | 2x rate (otomatik) |

C binary'de `CLOCK_MONOTONIC` tabanli token refill yapilir.

---

## 13. Packet Deduplication

Ayni paketi birden fazla TAP'tan alirsa sadece ilkini iletir.

| Parametre | Varsayilan | Aciklama |
|---|---|---|
| Window | 100 ms | Tekrar algilama suresi |
| Hash Bytes | 128 | Paketin kac byte'i hashlenecek |
| Tablo boyutu | 65536 entry | CRC32 hash tablosu |

**Konfigürasyon:** `dedup.conf` dosyasi C binary tarafindan okunur.
Format: `port,enabled,window_ms,hash_bytes` (port `*` = global)

---

## 14. SSL/TLS Inspection

Sifrelenmis trafigi decryption appliance'a yonlendirir.

**Zincir yapisi:**
```
Encrypted Port → Decrypt Tool Port → Reinject Port
     eth0     →       eth12        →     eth13
```

Her zincir 2 kural olusturur:
1. `eth0` → `eth12` (sifrelenmis trafigi tool'a gonder)
2. `eth12` → `eth13` (cozulmus trafigi geri enjekte et)

---

## 15. PCAP Capture

tcpdump ile paket yakalama.

| Sinir | Deger |
|---|---|
| Maks es zamanli | 3 capture |
| Maks sure | 300 saniye |
| Varsayilan sure | 60 saniye |
| Maks paket | 100,000 |

**Calistirilan komut:**
```bash
tcpdump -i <iface> -w <path>.pcap -c 100000 [bpf_filter]
```

Yakalanan dosyalar `captures/` klasorunde saklanir.

---

## 16. Alert & Monitoring

### Desteklenen Metrikler

| Metrik | Aciklama | Birim |
|---|---|---|
| `drop_rate` | Paket dusme orani | % (RxDrops/RxPPS*100) |
| `rx_errors` | Alinan hata sayisi | sayi |
| `link_down` | Port baglanti durumu | 1=down, 0=up |
| `cpu` | CPU kullanimi | % |
| `memory` | RAM kullanimi | % |

### Operatorler
- `>` Buyukse
- `<` Kucukse
- `=` Esitse

### Zamanlama
- Degerlendirme: **10 saniyede bir**
- Cooldown: **5 dakika** (ayni alert tekrar tetiklenmez)

### Webhook Formati

```json
POST <webhook_url>
Content-Type: application/json

{
  "alert": "High Drop Rate",
  "message": "[High Drop Rate] drop_rate on eth0: 7.50 > 5.00",
  "value": 7.5,
  "time": "2026-03-29T10:30:45Z"
}
```
Timeout: 5 saniye.

---

## 17. Health Checks

Tool output portlarini izler. Port down olursa o porta yonlendiren kurallar otomatik disable edilir.

| Parametre | Deger |
|---|---|
| Kontrol araligi | 5 saniye |
| Kaynak | `/sys/class/net/<iface>/operstate` |
| Auto-disable | Port down → kurallar pasif |
| Auto-enable | Port up → kurallar tekrar aktif |

---

## 18. Syslog / SIEM Entegrasyonu

### RFC 5424 Formati

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - - MSG
```

### Konfigürasyon

| Alan | Varsayilan | Aciklama |
|---|---|---|
| Server | - | Syslog sunucu IP/hostname |
| Port | 514 | Hedef port |
| Protocol | UDP | UDP veya TCP |
| Facility | LOCAL0 (16) | LOCAL0-LOCAL7 (16-23) |
| Source Name | packet-broker | SIEM'de gorunecek isim |

### Severity Mapping

| Log Seviyesi | RFC 5424 Severity |
|---|---|
| ERROR | 3 (Error) |
| WARN | 4 (Warning) |
| INFO | 6 (Informational) |
| DEBUG | 7 (Debug) |
| Alert Events | 4 (Warning) |

### Iletim Modlari

- **Forward Alerts:** Alert tetiklendiginde syslog'a gonder
- **Forward Logs:** packet_broker.log'a yazilan her satiri ilet (2sn polling)
- **Test Message:** Baglanti dogrulama icin test mesaji gonder

---

## 19. Cluster Mode

### Modlar

| Mod | Aciklama |
|---|---|
| `standalone` | Tekil cihaz (varsayilan) |
| `controller` | Merkezi yonetim noktasi |
| `node` | Controller'a baglanir |

### Controller Davranisi
- Node kayitlarini kabul eder (`POST /api/cluster/heartbeat`)
- 30 saniye heartbeat gelmezse node'u "offline" isaretler
- Her 15 saniyede kontrol yapar

### Node Davranisi
- Her 10 saniyede controller'a heartbeat gonderir
- Payload: node adi, adres, kural sayisi, broker durumu, uptime

### Ornek Konfigürasyon

**Controller cihaz:**
```
Mode: controller
Node Name: master-01
Node Address: 192.168.1.1:8005
```

**Node cihaz:**
```
Mode: node
Node Name: broker-02
Node Address: 192.168.1.10:8005
Controller URL: http://192.168.1.1:8005
```

---

## 20. Backup & Restore

### Otomatik Backup
Her kural degisikliginden once otomatik backup alinir. Son 20 auto-backup saklanir.

### Manuel Backup
System → Backups → **Create Backup** (aciklama ile)

### Restore
Backup tablosundan **Restore** tiklanir. Mevcut `rules.conf` uzerine yazilir.

### Import/Export
- **Export:** ZIP dosyasi indirilir (`rules.conf` icerir)
- **Import:** ZIP dosyasi yuklenebilir (maks 10MB)

---

## 21. Firmware Update

### Yukleme
1. System → Firmware
2. Yeni binary dosyasini sec
3. **Upload & Replace** tikla
4. Mevcut binary otomatik yedeklenir: `firmware_backups/packet_broker_YYYYMMDD_HHMMSS.bak`
5. Yeni binary aktif olur
6. **Broker'i yeniden baslat** (Stop → Start)

### Rollback
Firmware sayfasinda eski versiyonlarin listesinden **Rollback** tikla.

### Guvenlik
- SHA256 checksum hesaplanir ve goruntulenilir
- Minimum 1024 byte dosya boyutu kontrolu
- Otomatik `chmod 0755`

---

## 22. Audit Log

Tum onemli islemler kaydedilir:

| Islem | Detay |
|---|---|
| `login` | Kullanici girisi |
| `rule_add` | Kural ekleme |
| `rule_delete` | Kural silme |
| `firmware_upload` | Firmware yukleme |
| `firmware_rollback` | Firmware geri alma |
| `2fa_enabled` | 2FA etkinlestirme |
| `2fa_disabled` | 2FA devre disi birakma |

Son 5000 kayit saklanir, eski kayitlar otomatik silinir.
System → **Audit Log** sayfasinda goruntulenilir.

---

## 23. Log Rotation

Otomatik log dosyasi yonetimi:

| Parametre | Deger |
|---|---|
| Maks boyut | 10 MB |
| Maks yedek | 5 dosya |
| Kontrol araligi | 30 saniye |

Rotasyon sirasinda:
```
packet_broker.log              ← aktif (yeni bos dosya olusturulur)
packet_broker.log.20260329_103045  ← yedek
packet_broker.log.20260328_142200  ← yedek
...
```

---

## 24. Tema (Dark/Light)

Sidebar'daki kullanici bolumunde gunes/ay ikonuna tiklayarak degistirilebilir.

- **Dark** (varsayilan): GitHub dark renk paleti (#0d1117 arka plan)
- **Light**: Acik tema (#f6f8fa arka plan)
- `localStorage`'da saklanir, sayfa yenilemede korunur
- CSS Custom Properties ile tek seferde tum renkler degisir

---

## 25. JSON API Referansi

Tum API endpoint'leri oturum dogrulamasi gerektirir (cookie). Cluster heartbeat haric.

| Method | Endpoint | Aciklama |
|---|---|---|
| GET | `/api/stats` | Port istatistikleri + rates |
| GET | `/api/stats/sparkline` | 60 noktali sparkline verisi |
| GET | `/api/system` | CPU%, memory%, uptime |
| GET | `/api/traffic/24h` | 24 saatlik trafik gecmisi |
| GET | `/api/captures` | Capture oturumlari |
| GET | `/api/alerts/events` | Alert olaylari + unacked sayisi |
| GET | `/api/backups` | Backup listesi |
| GET | `/api/cluster/nodes` | Cluster node listesi |
| POST | `/api/cluster/heartbeat` | Node heartbeat (auth gerektirmez) |

### Ornek Response: `/api/stats`

```json
{
  "rates": {
    "eth0": { "rx_pps": 1500.5, "tx_pps": 800.2, "rx_bps": 125000, "tx_bps": 64000, "rx_drops": 0, "tx_drops": 0 },
    "eth1": { ... }
  },
  "stats": {
    "eth0": { "rx_packets": 5000000, "tx_packets": 2500000, "rx_bytes": 7500000000, ... }
  },
  "link_info": {
    "eth0": { "name": "eth0", "oper_state": "up", "speed": 10000, "duplex": "full", "mtu": 1500 }
  }
}
```

### Ornek Response: `/api/system`

```json
{
  "uptime": "15d 7h 23m",
  "cpu_percent": 12.5,
  "mem_total": 8589934592,
  "mem_used": 3221225472,
  "mem_percent": 37.5
}
```

---

## 26. Konfigürasyon Dosyalari

| Dosya | Aciklama | Olusturan |
|---|---|---|
| `rules.conf` | C binary kural dosyasi (22 alan CSV) | Go UI |
| `rules_state.json` | Tam kural state'i (JSON) | Go UI |
| `users.db` | SQLite veritabani | Go UI |
| `license.key` | Imzalanmis lisans dosyasi | keygen CLI |
| `dedup.conf` | Dedup konfigürasyonu | Go UI |
| `packet_broker.log` | Uygulama + C binary logu | Her ikisi |
| `packet_broker.status` | "running" veya "stopped" | C binary |
| `packet_broker.pid` | C binary PID | C binary |

### SQLite Tablolari (`users.db`)

```
users, totp_secrets, alert_rules, alert_events,
config_backups, port_groups, mirror_sessions,
throttle_config, ssl_chains, dedup_config,
cluster_nodes, cluster_config, syslog_config,
health_checks, auto_disabled_rules, audit_log
```

---

## 27. C Binary Teknik Detay

### Sabitler

| Sabit | Deger | Aciklama |
|---|---|---|
| `MAX_RULES` | 256 | Maks kural sayisi |
| `MAX_INTERFACES` | 48 | Maks interface sayisi |
| `SNAP_LEN` | 65535 | Maks paket yakalama boyutu |
| `DEDUP_TABLE_SIZE` | 65536 | Hash tablosu boyutu (2^16) |
| `STATS_INTERVAL` | 5 sn | Istatistik log araligi |

### Threading (libpcap)

- Her input interface icin ayri pthread
- `rules_lock` mutex ile kural erisimi
- `dedup_lock` mutex ile dedup tablosu erisimi
- Stats thread: her 5 saniyede per-rule istatistikleri loglar

### Kural Eslestirme Sirasi

1. Interface eslesmesi (`iface_in`)
2. MAC filtresi (dst, src)
3. VLAN ID filtresi
4. IP filtresi (src CIDR, dst CIDR)
5. Protokol filtresi (TCP/UDP/ICMP)
6. Port filtresi (TCP/UDP dest port)
7. TCP bayrak filtresi
8. String eslesmesi (payload'da memmem)
9. Exclude inversiyonu
10. Rate limit kontrolu (token bucket)
11. VLAN manipulasyonu (add/remove/change)
12. Truncation
13. Forward (pcap_inject)

---

## 28. Guvenlik Notlari

1. **HTTPS kullanin:** Production'da reverse proxy (nginx/caddy) ile TLS ekleyin
2. **Varsayilan sifreyi degistirin:** admin/admin ile ilk giriste uyari gorunur
3. **2FA etkinlestirin:** Admin hesaplar icin ozellikle onerilir
4. **Rate limiting aktif:** 5 basarisiz giris/dakika/IP
5. **CSRF korumasi:** Tum POST isteklerinde token dogrulamasi
6. **HttpOnly + SameSite=Strict cookie:** XSS ve CSRF'e karsi
7. **Audit log:** Tum degisiklikler kaydedilir
8. **Lisans dogrulamasi:** Ed25519 imza, hardware kilidi

---

## 29. Troubleshooting

### Web UI baslamiyorsa

```bash
# Port kullanimda mi?
lsof -i :8005

# Template dosyalari yerinde mi?
ls templates/*.html

# Log kontrol
tail -f packet_broker.log
```

### C binary baslamiyorsa

```bash
# Binary izinleri
chmod +x packet_broker

# libpcap yuklu mu?
ldconfig -p | grep libpcap

# Interface var mi?
ip link show
```

### Kurallar calismiyorsa

```bash
# rules.conf icerigini kontrol et
cat rules.conf

# C binary logu
grep "Loaded" packet_broker.log
grep "Rule" packet_broker.log
```

### License hatalari

```bash
# Hardware ID kontrol
go run cmd/keygen/main.go -hwid

# License dosya formati kontrol
cat license.key | python3 -m json.tool
```

---

## 30. Gelistirici Referansi

### Proje Yapisi

```
packet_broker/
├── main.go                     # 1400+ satir, tum handler'lar ve routing
├── go.mod                      # Go modül tanimı
├── internal/                   # 22 Go paketi
├── templates/                  # 20+ HTML template
├── c_src/                      # 2 C binary (libpcap + DPDK)
├── cmd/keygen/                 # Lisans anahtar araci
├── deploy/                     # Systemd service
├── captures/                   # PCAP dosyalari (runtime)
├── firmware_backups/           # Eski binary yedekleri (runtime)
└── old/                        # Arsivlenmis Python kodu
```

### Yeni Paket Ekleme Adimlari

1. `internal/yenipaket/yenipaket.go` olustur (Store struct + New constructor)
2. `main.go`'da import ekle
3. App struct'a alan ekle
4. PageData struct'a gerekli alanlar ekle
5. Handler fonksiyonlari yaz
6. `main()` icinde init (New() cagir, App'e ata)
7. Route'lar ekle (mux.HandleFunc)
8. Template olustur (`templates/yenipaket.html`)
9. `layout.html` sidebar'a nav-item ekle
10. `go build ./...` ile dogrula

### Middleware Zinciri

```
Client → securityHeaders → requireAuth → requireCSRF → mux → handler
```

### Template Sistemi

- `{{template "header" .}}` ve `{{template "footer" .}}` ile layout
- Tum sayfalar PageData struct alir
- `login.html` ayri template set (layout'tan bagimsiz)
- Template fonksiyonlari: `add`, `sub`, `mul`, `min`, `fmtBytes`, `join`
