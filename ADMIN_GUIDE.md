# Packet Broker — Admin & Developer Guide

Comprehensive administration, configuration, licensing, and developer guide.

---

## Table of Contents

1. [Installation & Build](#1-installation--build)
2. [First Run](#2-first-run)
3. [Production Deployment with systemd](#3-production-deployment-with-systemd)
4. [User Management & Roles](#4-user-management--roles)
5. [Two-Factor Authentication (2FA/TOTP)](#5-two-factor-authentication-2fatotp)
6. [License System](#6-license-system)
7. [Rule Management](#7-rule-management)
8. [VLAN Manipulation](#8-vlan-manipulation)
9. [Packet Filtering (Extended)](#9-packet-filtering-extended)
10. [Traffic Mirroring (SPAN)](#10-traffic-mirroring-span)
11. [Load Balancing](#11-load-balancing)
12. [Bandwidth Throttling](#12-bandwidth-throttling)
13. [Packet Deduplication](#13-packet-deduplication)
14. [SSL/TLS Inspection](#14-ssltls-inspection)
15. [PCAP Capture](#15-pcap-capture)
16. [Alert & Monitoring](#16-alert--monitoring)
17. [Health Checks](#17-health-checks)
18. [Syslog / SIEM Integration](#18-syslog--siem-integration)
19. [Cluster Mode](#19-cluster-mode)
20. [Backup & Restore](#20-backup--restore)
21. [Firmware Update](#21-firmware-update)
22. [Audit Log](#22-audit-log)
23. [Log Rotation](#23-log-rotation)
24. [Theme (Dark/Light)](#24-theme-darklight)
25. [JSON API Reference](#25-json-api-reference)
26. [Configuration Files](#26-configuration-files)
27. [C Binary Technical Details](#27-c-binary-technical-details)
28. [Security Notes](#28-security-notes)
29. [Troubleshooting](#29-troubleshooting)
30. [Developer Reference](#30-developer-reference)

---

## 1. Installation & Build

### Requirements

- Go 1.22+ (for the web UI)
- GCC + libpcap-dev (for the C binary)
- Linux (production, for access to /proc/net/dev and /sys/class/net)
- macOS supported (development; netstats/sysinfo degrade)

### Building the Go Web UI

```bash
# Standard build
go build -o packet_broker_ui .

# ARM64 cross-compile (for embedded hardware)
GOOS=linux GOARCH=arm64 go build -o packet_broker_ui .

# ARM32 (Raspberry Pi etc.)
GOOS=linux GOARCH=arm GOARM=7 go build -o packet_broker_ui .
```

### Building the C Binary (libpcap)

```bash
# x86_64 Linux
gcc -O2 -o packet_broker c_src/packet_broker_libpcap.c -lpcap -lpthread

# ARM64 cross-compile
aarch64-linux-gnu-gcc -O2 -o packet_broker c_src/packet_broker_libpcap.c -lpcap -lpthread
```

### Building the C Binary (DPDK)

```bash
gcc -O2 -o packet_broker c_src/packet_broker.c $(pkg-config --cflags --libs libdpdk) -lpthread

# Run (root and hugepages required)
sudo ./packet_broker -l 0-3 -n 4 --
```

---

## 2. First Run

```bash
# The following files must be in the working directory:
# - packet_broker_ui    (Go binary)
# - packet_broker       (C binary)
# - templates/          (HTML template folder)

./packet_broker_ui
```

**Default settings:**
- Web UI: `http://localhost:8005`
- Default user: `admin` / `admin`
- Automatically created files:
  - `users.db` — SQLite database (users, alerts, backups, etc.)
  - `packet_broker.log` — Application log
  - `packet_broker.status` — Broker status ("running"/"stopped")
  - `rules.conf` — Rule file for the C binary
  - `rules_state.json` — Full rule state (JSON)

> **WARNING:** Change the `admin/admin` password on first login! A yellow warning will appear on the dashboard.

---

## 3. Production Deployment with systemd

### File Layout

```bash
# Create the target directory
sudo mkdir -p /opt/packet-broker
sudo cp packet_broker_ui packet_broker /opt/packet-broker/
sudo cp -r templates/ /opt/packet-broker/

# Install the systemd service
sudo cp deploy/packet-broker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable packet-broker
sudo systemctl start packet-broker
```

### Service Status

```bash
sudo systemctl status packet-broker
sudo journalctl -u packet-broker -f        # live log
sudo systemctl restart packet-broker       # restart
```

### Service Configuration

File: `/etc/systemd/system/packet-broker.service`

| Parameter | Value | Description |
|---|---|---|
| `WorkingDirectory` | `/opt/packet-broker` | Working directory |
| `Restart` | `always` | Automatically restart on every crash |
| `RestartSec` | `5` | 5-second wait |
| `LimitNOFILE` | `65536` | File descriptor limit |
| `GOMAXPROCS` | `4` | Go thread count |
| `ProtectSystem` | `strict` | Only ReadWritePaths are writable |
| `NoNewPrivileges` | `true` | Privilege escalation is blocked |

---

## 4. User Management & Roles

### Roles

| Role | Permissions |
|---|---|
| `admin` | All operations: adding/deleting rules, user management, system settings |
| `user` | Read-only: dashboard, rules (no delete/add), operational logs |

### User Operations (Web UI → Users)

- **Add:** Username, password (min 8 characters), role selection
- **Change password:** Admin can change any user's password
- **Delete:** The last admin account cannot be deleted; an admin cannot delete themselves

### Session & Security

| Parameter | Value |
|---|---|
| Session duration | 24 hours |
| Cookie | `HttpOnly`, `SameSite=Strict` |
| Password hashing | bcrypt, cost=12 |
| Login rate limit | 5 attempts/minute/IP |
| CSRF protection | Session-based token, constant-time comparison |
| Timing attack | bcrypt is run even for nonexistent users |

---

## 5. Two-Factor Authentication (2FA/TOTP)

### Enabling

1. Go to the **Profile** page
2. View the secret key in the "Two-Factor Authentication" section
3. Add it to the Google Authenticator or Authy app
4. Enter the 6-digit code from the app and click **Verify & Enable**

### Technical Details

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA1 (RFC 6238) |
| Code length | 6 digits |
| Period | 30 seconds |
| Tolerance | ±1 step (±30 seconds) |
| Secret key | 160-bit, Base32 encoded |

### QR URI Format

```
otpauth://totp/PacketBroker:username?secret=BASE32SECRET&issuer=PacketBroker&digits=6&period=30
```

### Disabling

Profile → Two-Factor Authentication → **Disable 2FA**

---

## 6. License System

### Overview

The license system is based on Ed25519 digital signatures. Every device has a unique Hardware ID. The license is locked to this ID.

### Step 1: Generate the Vendor Key Pair (ONE TIME)

```bash
go run cmd/keygen/main.go -generate-keys
```

Output:
```
=== Ed25519 Key Pair ===

PUBLIC KEY (embed in license.go vendorPubKeyHex):
a1b2c3d4e5f6...  (64 hex characters)

PRIVATE KEY (keep SECRET, use for signing):
f6e5d4c3b2a1...  (128 hex characters)
```

> **CRITICAL:** Store the private key in a secure location. Paste the public key into the `vendorPubKeyHex` variable in the `internal/license/license.go` file and rebuild.

### Step 2: Embed the Public Key into the Binary

File: `internal/license/license.go`, around line 67:

```go
var vendorPubKeyHex = "a1b2c3d4e5f6..."  // 64 hex characters
```

After changing it, rebuild:
```bash
go build -o packet_broker_ui .
```

### Step 3: Obtain the Customer's Hardware ID

On the customer's device:
```bash
./packet_broker_ui  # start it and check the System → License page in the web UI
# or
go run cmd/keygen/main.go -hwid
```

Hardware ID example: `a7f3c92b1d4e8f0612345678abcdef90` (32 hex characters)

### Step 4: Generate the License

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

### License Parameters

| Parameter | Description | Examples |
|---|---|---|
| `-privkey` | Vendor private key (128 hex) | Required |
| `-hardware-id` | Target device HWID (32 hex) | Leave empty = all devices |
| `-customer` | Customer name | "ACME Corp" |
| `-type` | License type | `trial`, `standard`, `enterprise` |
| `-features` | Feature list (comma-separated) | `all` or `mirror,ssl,cluster,dedup,throttle` |
| `-ports` | Maximum number of ports | `24`, `48`, `0` (unlimited) |
| `-expiry` | Expiration date | `2027-01-01` or `perpetual` |
| `-out` | Output file path | `license.key` |

### Step 5: Upload the License

1. Web UI → System → **License** page
2. Upload the `license.key` file with **Upload & Activate**
3. The license status and details will be displayed

### Example Licenses

```bash
# Trial (30 days, limited features)
go run cmd/keygen/main.go -sign \
  -privkey "$PRIVKEY" \
  -hardware-id "$HWID" \
  -customer "Demo User" \
  -type trial \
  -features "mirror,throttle" \
  -ports 8 \
  -expiry "2026-04-28"

# Enterprise (unlimited, all features, perpetual)
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

### How Is the Hardware ID Computed?

A SHA256 hash is taken sequentially from the following sources:
1. All MAC addresses (sorted, loopback excluded)
2. `/etc/machine-id` or `/var/lib/dbus/machine-id`
3. `/sys/class/dmi/id/product_serial` (OEM text excluded)
4. Fallback: hostname + CPU architecture + OS

Result: first 16 bytes → 32 hex characters

### License File Format

```json
{
  "payload": "base64_encoded_json...",
  "signature": "base64_encoded_ed25519_signature..."
}
```

When the payload is decoded:
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

## 7. Rule Management

### Rule Adding Methods

1. **Topology Drag-and-Drop:** Drag and drop from a left port to a right port
2. **Manual Modal:** The "Manual" button on the Rules page
3. **JSON API:** `POST /add-rule` (form data)

### Rule Fields (22 fields)

| # | Field | Type | Default | Description |
|---|---|---|---|---|
| 1 | `interface_in` | string | - | Input interface (eth0, eth1...) |
| 2 | `tcp_flags` | string | "0" | TCP flags: S(YN), A(CK), F(IN), R(ST), P(USH), U(RG) |
| 3 | `dest_port` | string | "0" | Destination port (0 = all) |
| 4 | `protocol` | string | "0" | TCP, UDP, ICMP (0 = all) |
| 5 | `vlan_id` | string | "0" | VLAN ID filter (0 = all) |
| 6 | `string_match` | string | "0" | String search in the payload |
| 7 | `exclude` | string | "0" | "1" = EXCLUDE matching packets |
| 8 | `interface_out` | string | - | Output interface |
| 9 | `enabled` | bool | true | Whether the rule is active |
| 10 | `priority` | int | auto | Priority (0 = highest) |
| 11 | `vlan_action` | string | "none" | none, add, remove, change |
| 12 | `vlan_new_id` | string | "0" | Target VLAN ID (for add/change) |
| 13 | `truncate` | string | "0" | Packet truncation (bytes), 0 = full |
| 14 | `src_ip` | string | "0" | Source IP (CIDR: 192.168.1.0/24) |
| 15 | `dst_ip` | string | "0" | Destination IP (CIDR) |
| 16 | `src_mac` | string | "0" | Source MAC (AA:BB:CC:DD:EE:FF) |
| 17 | `dst_mac` | string | "0" | Destination MAC |
| 18 | `bpf_filter` | string | "" | BPF filter expression |
| 19 | `rate_limit_mbps` | string | "0" | Bandwidth limit (Mbps) |
| 20 | `rate_limit_pps` | string | "0" | Packet rate limit (pps) |
| 21 | `mirror_ports` | string | "" | Additional output ports (comma-separated) |
| 22 | `dedup_key` | string | "0" | Dedup group key |

### Rule Ordering

- Rules are processed in priority order (the Priority field)
- Ordering can be done via drag-and-drop in the Web UI
- `POST /rules/reorder` JSON body: `{"order":[2,0,1,3]}`

### Rule Enable/Disable

- Each rule can be made active/inactive
- Inactive rules are not written to `rules.conf` (the C binary does not see them)
- Toggled via `POST /rules/{index}/toggle`

### File Structure

```
rules_state.json  ← Source (JSON, all fields, including disabled)
       ↓ writeCSV()
rules.conf        ← Derived (22-field CSV, only enabled rules)
       ↓ read by the C binary
packet_broker     ← Packet processing
```

---

## 8. VLAN Manipulation

| Action | Description | Packet Change |
|---|---|---|
| `none` | No change | — |
| `add` | Add VLAN tag | A 4-byte 802.1Q header is added |
| `remove` | Remove VLAN tag | A 4-byte 802.1Q header is removed |
| `change` | Change VLAN ID | The VID in the TCI field changes, priority is preserved |

**802.1Q frame structure:**
```
[Dst MAC 6B][Src MAC 6B][0x8100 2B][TCI 2B][EtherType 2B][Payload...]
                                     ↑
                              Priority(3) + VID(12)
```

---

## 9. Packet Filtering (Extended)

### IP Filter (CIDR supported)
```
src_ip = 192.168.1.0/24    # between 192.168.1.0 - 192.168.1.255
dst_ip = 10.0.0.1           # single IP (/32 default)
```

### MAC Filter
```
src_mac = AA:BB:CC:DD:EE:FF
dst_mac = 00:11:22:33:44:55
```

### TCP Flag Combinations
```
S     = SYN (connection start)
SA    = SYN+ACK (connection accepted)
A     = ACK
F     = FIN (connection close)
R     = RST (reset)
P     = PSH (data push)
```

### Recommended Packet Truncation Values
```
64    = Only Ethernet + IP header
128   = Header + some TCP/UDP information
256   = Sufficient for most headers
0     = Full packet (default)
```

---

## 10. Traffic Mirroring (SPAN)

Copies all traffic coming from a single input port to N destination ports.

**Creation:** Network → Mirror / SPAN
- **Source port:** The interface whose traffic will be monitored
- **Destination ports:** Comma-separated output ports

**Example:** `eth0` → `eth12, eth13, eth14` (copy to 3 tools)

A rule is automatically created for each src→dst pair (no filter = all traffic).

---

## 11. Load Balancing

| Mode | Description |
|---|---|
| Round-Robin | Packets are distributed in turn |
| Hash | Distributed by source/destination IP hash |

**Creation:** Network → Load Balance
- Group name, mode, input ports, output ports

---

## 12. Bandwidth Throttling

Per-rule rate limiting with the token bucket algorithm.

| Parameter | Description |
|---|---|
| Max Mbps | Bandwidth limit (0 = unlimited) |
| Max PPS | Packets/second limit (0 = unlimited) |
| Burst | 2x rate (automatic) |

Token refill based on `CLOCK_MONOTONIC` is performed in the C binary.

---

## 13. Packet Deduplication

If it receives the same packet from more than one TAP, it forwards only the first one.

| Parameter | Default | Description |
|---|---|---|
| Window | 100 ms | Duplicate detection duration |
| Hash Bytes | 128 | How many bytes of the packet are hashed |
| Table size | 65536 entries | CRC32 hash table |

**Configuration:** The `dedup.conf` file is read by the C binary.
Format: `port,enabled,window_ms,hash_bytes` (port `*` = global)

---

## 14. SSL/TLS Inspection

Redirects encrypted traffic to a decryption appliance.

**Chain structure:**
```
Encrypted Port → Decrypt Tool Port → Reinject Port
     eth0     →       eth12        →     eth13
```

Each chain creates 2 rules:
1. `eth0` → `eth12` (send encrypted traffic to the tool)
2. `eth12` → `eth13` (reinject the decrypted traffic)

---

## 15. PCAP Capture

Packet capture with tcpdump.

| Limit | Value |
|---|---|
| Max concurrent | 3 captures |
| Max duration | 300 seconds |
| Default duration | 60 seconds |
| Max packets | 100,000 |

**Command executed:**
```bash
tcpdump -i <iface> -w <path>.pcap -c 100000 [bpf_filter]
```

Captured files are stored in the `captures/` folder.

---

## 16. Alert & Monitoring

### Supported Metrics

| Metric | Description | Unit |
|---|---|---|
| `drop_rate` | Packet drop rate | % (RxDrops/RxPPS*100) |
| `rx_errors` | Number of receive errors | count |
| `link_down` | Port link status | 1=down, 0=up |
| `cpu` | CPU usage | % |
| `memory` | RAM usage | % |

### Operators
- `>` Greater than
- `<` Less than
- `=` Equal to

### Timing
- Evaluation: **every 10 seconds**
- Cooldown: **5 minutes** (the same alert is not triggered again)

### Webhook Format

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
Timeout: 5 seconds.

---

## 17. Health Checks

Monitors tool output ports. If a port goes down, the rules that route to that port are automatically disabled.

| Parameter | Value |
|---|---|
| Check interval | 5 seconds |
| Source | `/sys/class/net/<iface>/operstate` |
| Auto-disable | Port down → rules inactive |
| Auto-enable | Port up → rules active again |

---

## 18. Syslog / SIEM Integration

### RFC 5424 Format

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID - - MSG
```

### Configuration

| Field | Default | Description |
|---|---|---|
| Server | - | Syslog server IP/hostname |
| Port | 514 | Destination port |
| Protocol | UDP | UDP or TCP |
| Facility | LOCAL0 (16) | LOCAL0-LOCAL7 (16-23) |
| Source Name | packet-broker | Name that will appear in the SIEM |

### Severity Mapping

| Log Level | RFC 5424 Severity |
|---|---|
| ERROR | 3 (Error) |
| WARN | 4 (Warning) |
| INFO | 6 (Informational) |
| DEBUG | 7 (Debug) |
| Alert Events | 4 (Warning) |

### Forwarding Modes

- **Forward Alerts:** Send to syslog when an alert is triggered
- **Forward Logs:** Forward every line written to packet_broker.log (2s polling)
- **Test Message:** Send a test message to verify the connection

---

## 19. Cluster Mode

### Modes

| Mode | Description |
|---|---|
| `standalone` | Single device (default) |
| `controller` | Central management point |
| `node` | Connects to the controller |

### Controller Behavior
- Accepts node registrations (`POST /api/cluster/heartbeat`)
- Marks a node "offline" if no heartbeat arrives for 30 seconds
- Performs a check every 15 seconds

### Node Behavior
- Sends a heartbeat to the controller every 10 seconds
- Payload: node name, address, rule count, broker status, uptime

### Example Configuration

**Controller device:**
```
Mode: controller
Node Name: master-01
Node Address: 192.168.1.1:8005
```

**Node device:**
```
Mode: node
Node Name: broker-02
Node Address: 192.168.1.10:8005
Controller URL: http://192.168.1.1:8005
```

---

## 20. Backup & Restore

### Automatic Backup
An automatic backup is taken before every rule change. The last 20 auto-backups are retained.

### Manual Backup
System → Backups → **Create Backup** (with a description)

### Restore
Click **Restore** from the backup table. It overwrites the existing `rules.conf`.

### Import/Export
- **Export:** A ZIP file is downloaded (contains `rules.conf`)
- **Import:** A ZIP file can be uploaded (max 10MB)

---

## 21. Firmware Update

### Upload
1. System → Firmware
2. Select the new binary file
3. Click **Upload & Replace**
4. The existing binary is automatically backed up: `firmware_backups/packet_broker_YYYYMMDD_HHMMSS.bak`
5. The new binary becomes active
6. **Restart the broker** (Stop → Start)

### Rollback
Click **Rollback** from the list of old versions on the Firmware page.

### Security
- A SHA256 checksum is computed and displayed
- Minimum 1024-byte file size check
- Automatic `chmod 0755`

---

## 22. Audit Log

All important operations are recorded:

| Operation | Detail |
|---|---|
| `login` | User login |
| `rule_add` | Rule addition |
| `rule_delete` | Rule deletion |
| `firmware_upload` | Firmware upload |
| `firmware_rollback` | Firmware rollback |
| `2fa_enabled` | 2FA enabled |
| `2fa_disabled` | 2FA disabled |

The last 5000 records are retained; older records are automatically deleted.
Displayed on the System → **Audit Log** page.

---

## 23. Log Rotation

Automatic log file management:

| Parameter | Value |
|---|---|
| Max size | 10 MB |
| Max backups | 5 files |
| Check interval | 30 seconds |

During rotation:
```
packet_broker.log              ← active (a new empty file is created)
packet_broker.log.20260329_103045  ← backup
packet_broker.log.20260328_142200  ← backup
...
```

---

## 24. Theme (Dark/Light)

Can be changed by clicking the sun/moon icon in the user section of the sidebar.

- **Dark** (default): GitHub dark color palette (#0d1117 background)
- **Light**: Light theme (#f6f8fa background)
- Stored in `localStorage`, preserved across page reloads
- All colors change at once via CSS Custom Properties

---

## 25. JSON API Reference

All API endpoints require session authentication (cookie). Except the cluster heartbeat.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/stats` | Port statistics + rates |
| GET | `/api/stats/sparkline` | 60-point sparkline data |
| GET | `/api/system` | CPU%, memory%, uptime |
| GET | `/api/traffic/24h` | 24-hour traffic history |
| GET | `/api/captures` | Capture sessions |
| GET | `/api/alerts/events` | Alert events + unacked count |
| GET | `/api/backups` | Backup list |
| GET | `/api/cluster/nodes` | Cluster node list |
| POST | `/api/cluster/heartbeat` | Node heartbeat (does not require auth) |

### Example Response: `/api/stats`

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

### Example Response: `/api/system`

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

## 26. Configuration Files

| File | Description | Created by |
|---|---|---|
| `rules.conf` | C binary rule file (22-field CSV) | Go UI |
| `rules_state.json` | Full rule state (JSON) | Go UI |
| `users.db` | SQLite database | Go UI |
| `license.key` | Signed license file | keygen CLI |
| `dedup.conf` | Dedup configuration | Go UI |
| `packet_broker.log` | Application + C binary log | Both |
| `packet_broker.status` | "running" or "stopped" | C binary |
| `packet_broker.pid` | C binary PID | C binary |

### SQLite Tables (`users.db`)

```
users, totp_secrets, alert_rules, alert_events,
config_backups, port_groups, mirror_sessions,
throttle_config, ssl_chains, dedup_config,
cluster_nodes, cluster_config, syslog_config,
health_checks, auto_disabled_rules, audit_log
```

---

## 27. C Binary Technical Details

### Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_RULES` | 256 | Max number of rules |
| `MAX_INTERFACES` | 48 | Max number of interfaces |
| `SNAP_LEN` | 65535 | Max packet capture size |
| `DEDUP_TABLE_SIZE` | 65536 | Hash table size (2^16) |
| `STATS_INTERVAL` | 5 s | Statistics log interval |

### Threading (libpcap)

- A separate pthread for each input interface
- Rule access via the `rules_lock` mutex
- Dedup table access via the `dedup_lock` mutex
- Stats thread: logs per-rule statistics every 5 seconds

### Rule Matching Order

1. Interface match (`iface_in`)
2. MAC filter (dst, src)
3. VLAN ID filter
4. IP filter (src CIDR, dst CIDR)
5. Protocol filter (TCP/UDP/ICMP)
6. Port filter (TCP/UDP dest port)
7. TCP flag filter
8. String match (memmem in the payload)
9. Exclude inversion
10. Rate limit check (token bucket)
11. VLAN manipulation (add/remove/change)
12. Truncation
13. Forward (pcap_inject)

---

## 28. Security Notes

1. **Use HTTPS:** In production, add TLS with a reverse proxy (nginx/caddy)
2. **Change the default password:** A warning appears on the first login with admin/admin
3. **Enable 2FA:** Especially recommended for admin accounts
4. **Rate limiting active:** 5 failed logins/minute/IP
5. **CSRF protection:** Token validation on all POST requests
6. **HttpOnly + SameSite=Strict cookie:** Against XSS and CSRF
7. **Audit log:** All changes are recorded
8. **License validation:** Ed25519 signature, hardware lock

---

## 29. Troubleshooting

### If the Web UI does not start

```bash
# Is the port in use?
lsof -i :8005

# Are the template files in place?
ls templates/*.html

# Check the log
tail -f packet_broker.log
```

### If the C binary does not start

```bash
# Binary permissions
chmod +x packet_broker

# Is libpcap installed?
ldconfig -p | grep libpcap

# Does the interface exist?
ip link show
```

### If rules do not work

```bash
# Check the contents of rules.conf
cat rules.conf

# C binary log
grep "Loaded" packet_broker.log
grep "Rule" packet_broker.log
```

### License errors

```bash
# Check the Hardware ID
go run cmd/keygen/main.go -hwid

# Check the license file format
cat license.key | python3 -m json.tool
```

---

## 30. Developer Reference

### Project Structure

```
packet_broker/
├── main.go                     # 1400+ lines, all handlers and routing
├── go.mod                      # Go module definition
├── internal/                   # 22 Go packages
├── templates/                  # 20+ HTML templates
├── c_src/                      # 2 C binaries (libpcap + DPDK)
├── cmd/keygen/                 # License key tool
├── deploy/                     # Systemd service
├── captures/                   # PCAP files (runtime)
├── firmware_backups/           # Old binary backups (runtime)
└── old/                        # Archived Python code
```

### Steps to Add a New Package

1. Create `internal/yenipaket/yenipaket.go` (Store struct + New constructor)
2. Add the import in `main.go`
3. Add a field to the App struct
4. Add the necessary fields to the PageData struct
5. Write the handler functions
6. Initialize inside `main()` (call New(), assign to App)
7. Add routes (mux.HandleFunc)
8. Create the template (`templates/yenipaket.html`)
9. Add a nav-item to the `layout.html` sidebar
10. Verify with `go build ./...`

### Middleware Chain

```
Client → securityHeaders → requireAuth → requireCSRF → mux → handler
```

### Template System

- Layout via `{{template "header" .}}` and `{{template "footer" .}}`
- All pages receive a PageData struct
- `login.html` is a separate template set (independent of the layout)
- Template functions: `add`, `sub`, `mul`, `min`, `fmtBytes`, `join`
