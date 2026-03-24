# SSTB — Smart Security & Threat Blocker

> Advanced Multi-MikroTik Security Platform

Sistem keamanan proaktif untuk MikroTik RouterOS yang mengintegrasikan threat intelligence eksternal (VirusTotal, AlienVault OTX, ThreatFox, CISA KEV/NVD) dengan geolokasi IP, deteksi otomatis, dan manajemen multi-router dari satu dashboard.

---

> **PENTING:** Deploy aplikasi ini di lingkungan terisolasi (intranet) untuk menghindari potensi penyalahgunaan API key threat intel.

---

## Arsitektur

```
┌──────────────────────────────────────────────────────────────┐
│                        Docker Compose                        │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐  │
│  │ Frontend │    │ Backend  │    │        Worker          │  │
│  │ Next.js  │◄──►│ FastAPI  │◄──►│  Celery + Redis        │  │
│  │  :3000   │    │  :8080   │    │  (ThreatFox / NVD /    │  │
│  └──────────┘    └────┬─────┘    │   CISA KEV / AlienVault│  │
│                       │          │   cleanup expired IPs) │  │
│  ┌──────────┐    ┌────▼─────┐    └────────────────────────┘  │
│  │  Syslog  │───►│PostgreSQL│    ┌────────────────────────┐  │
│  │ UDP :514 │    │    DB    │    │        Redis           │  │
│  └──────────┘    └──────────┘    │   (broker / cache)     │  │
└──────────────────────────────────└────────────────────────┘──┘
         ▲                                    ▼
   MikroTik Syslog               MikroTik REST API (multi-device)
   (firewall logs)               Block/Unblock · Interfaces · DHCP
                                 Firewall Rules · System Logs
```

---

## Fitur Utama

### Threat Intelligence
| Sumber | Data |
|---|---|
| **VirusTotal** | Detection engines, reputation, network ASN |
| **AlienVault OTX** | Pulses, malware families, adversaries, tags |
| **ThreatFox** | IoC matches, malware names, confidence score |
| **ip-api.com** | Geolokasi (lat/lon, ISP, ASN, timezone, proxy/hosting) |
| **CISA KEV** | Known Exploited Vulnerabilities (MikroTik/router focused) |
| **NVD** | CVE MikroTik RouterOS (CVSS score, severity) |

**Scoring:** VT 40% · AlienVault 45% · ThreatFox 15%
**Threshold:** Score ≥ 5.0 → `is_malicious: true`

> AbuseIPDB tidak diikutsertakan dalam scoring — tanpa API key nilainya selalu 0.0 yang menurunkan total skor IP berbahaya secara signifikan.

### Multi-MikroTik Management
- Tambah/edit/hapus beberapa router MikroTik dari satu panel Settings
- Test koneksi per-device: model, versi, uptime, CPU, memori, jumlah interface
- Set router default untuk operasi block/unblock otomatis
- Auto-setup firewall DROP rules (`SSTB-AutoBlock-Input/Forward`) saat device ditambah
- Topology SVG real-time: status online/offline, animasi koneksi aktif
- Device selector di tab MikroTik Monitor — switch antar router tanpa pindah halaman
- Default device di-load dari DB saat startup (tanpa butuh env vars)

### Dashboard (8 Tab)
- **Overview** — Stats, Attack Timeline, Hourly Heatmap, Top Attackers, Live Feed
- **IP Blocklist** — Kelola IP yang diblokir, scan TI, filter; geo+threat enrichment otomatis saat block manual
- **Attack Logs** — Log serangan dengan filter status/tipe/negara/score
- **CVE Alerts** — CVE MikroTik, KEV filter, CVSS score; disync dari NVD & CISA KEV
- **MikroTik Monitor** — Device selector, Interfaces, Firewall Rules (toggle), NAT, DHCP, Connections, System Logs
- **Geo Analytics** — Top negara penyerang, protocol breakdown, distribusi threat score
- **Whitelist** — Manajemen IP whitelist + sync dua arah ke MikroTik
- **Settings** — Multi-device CRUD, test koneksi, setup firewall rules, Topology SVG

### Worker (Celery Beat)
| Schedule | Task |
|---|---|
| 02:00 UTC | Sync ThreatFox IoCs → ingest ke backend |
| 03:00 UTC | Sync NVD CVEs (MikroTik RouterOS) → simpan ke DB |
| 04:00 UTC | Sync AlienVault OTX pulses → ingest IPv4 indicators |
| 05:00 UTC | Sync CISA KEV catalog → simpan entri MikroTik-related |
| Setiap jam | Cleanup blocked IPs yang sudah expired |

### Keamanan
- IP validation (Pydantic) pada semua input address — tolak string non-IP
- `is_admin` default `False` — user baru bukan admin otomatis
- Geo enrichment otomatis saat Block IP manual (country, ISP, threat score)
- Upsert blocked IP — re-block IP yang pernah di-unblock tidak error UniqueViolation

---

## Alur Kerja (Flow)

```
MikroTik Firewall Log
        │
        ▼ UDP 514
  Syslog Receiver
        │
        ▼ HTTP POST /threats/ingest
   Backend FastAPI
        │
        ├── Cek Whitelist → skip jika ada
        ├── Cek ThreatIntelCache lokal → block langsung jika malicious
        │
        ▼ Background Task
  analyze_and_block()
        │
        ├── VT + AlienVault + ThreatFox + GeoIP (parallel, asyncio)
        ├── Klasifikasi kategori (brute-force, botnet, malware-c2, ...)
        ├── Hitung weighted score (VT 40% · AV 45% · TF 15%)
        │
        ├── score ≥ 5.0 → auto_block_ip()
        │       └── Simpan ke DB + push ke MikroTik SSTB-Blacklist (via PUT)
        │
        └── Update AttackLog, ThreatIntelCache, broadcast WebSocket
```

---

## Instalasi

### 1. Clone & Konfigurasi

```bash
git clone https://github.com/rezayw/SSTB.git
cd SSTB
cp .env.example .env.local
```

Edit `.env.local` — minimal yang wajib:

```env
SECRET_KEY=<python3 -c "import secrets; print(secrets.token_hex(32))">
DB_USER=sstb
DB_PASSWORD=password-kuat-tanpa-karakter-khusus
DB_NAME=sstb

# Opsional — MikroTik ditambah via Settings tab di dashboard
# MIKROTIK_API_URL=https://192.168.X.X/
# MIKROTIK_API_USER=sstb-api
# MIKROTIK_API_PASSWORD=password-mikrotik

# Threat Intelligence (sangat direkomendasikan)
VIRUSTOTAL_API_KEY=...
ALIENVAULT_API_KEY=...
THREAT_FOX_API_KEY=...
NVD_API_KEY=...
```

> **Penting:** `DB_PASSWORD` tidak boleh mengandung karakter `@` — akan merusak DATABASE_URL.

### 2. Build & Jalankan

```bash
docker compose --env-file .env.local build
docker compose --env-file .env.local up -d
```

### 3. Seed Admin

> **Catatan:** Pembuatan akun admin hanya dilakukan via database — tidak ada halaman register di frontend. Gunakan perintah di bawah ini untuk membuat akun pertama.

```bash
HASH=$(docker run --rm python:3.11-slim sh -c \
  "pip install passlib bcrypt==4.0.1 -q && python3 -c \
  \"from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('admin1234'))\"" 2>/dev/null)

docker compose --env-file .env.local exec db psql -U sstb -d sstb -c \
  "INSERT INTO users (email, username, hashed_password, is_active, is_admin)
   VALUES ('admin@sstb.local', 'admin', '$HASH', true, true)
   ON CONFLICT (username) DO UPDATE SET hashed_password = EXCLUDED.hashed_password;"
```

### 4. Akses

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8080 |
| Swagger Docs | http://localhost:8080/docs |

### 5. Tambah MikroTik Device

Buka **Settings** tab → klik **+ Add Device** → isi:
- Name, Host/IP, Port (443), API User, API Password
- Centang **Use SSL** dan **Set as Default**
- Klik **Add & Test Connection** — koneksi ditest, firewall DROP rules dibuat otomatis

### 6. Setup Firewall Rules (jika belum otomatis)

Di Settings tab, klik **🛡 Setup FW** pada device yang diinginkan. Ini akan membuat:
- `SSTB-AutoBlock-Input` — DROP inbound dari SSTB-Blacklist
- `SSTB-AutoBlock-Forward` — DROP forward dari SSTB-Blacklist
- `SSTB-AutoBlock-Forward-Dst` — DROP forward ke SSTB-Blacklist

---

## Konfigurasi MikroTik

### Aktifkan REST API

```routeros
/ip service enable www-ssl
/ip service set www-ssl port=443
```

### Buat API User (jangan pakai admin)

```routeros
/user group add name=sstb-api policy=read,write,api
/user add name=sstb group=sstb-api password=<password-kuat>
```

### Aktifkan Syslog ke SSTB

```routeros
/system logging action add name=sstb-syslog target=remote \
  remote=<IP-SERVER-SSTB> remote-port=514 bsd-syslog=yes
/system logging add action=sstb-syslog topics=firewall
```

### Firewall Drop Rules (otomatis via SSTB atau manual)

```routeros
/ip firewall filter add chain=input src-address-list=SSTB-Blacklist \
  action=drop comment="SSTB-AutoBlock-Input" place-before=0
/ip firewall filter add chain=forward src-address-list=SSTB-Blacklist \
  action=drop comment="SSTB-AutoBlock-Forward"
/ip firewall filter add chain=forward dst-address-list=SSTB-Blacklist \
  action=drop comment="SSTB-AutoBlock-Forward-Dst"
```

> **RouterOS 7:** MikroTik REST API menggunakan `PUT` untuk membuat entri baru di address-list. `POST` mengembalikan `400 "no such command"`. SSTB sudah menggunakan `PUT` dengan benar.

---

## Variabel Environment

| Variabel | Wajib | Keterangan |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key, min. 32 karakter |
| `DB_USER` | ✅ | PostgreSQL username |
| `DB_PASSWORD` | ✅ | PostgreSQL password (tanpa karakter `@`) |
| `DB_NAME` | ✅ | Nama database |
| `MIKROTIK_API_URL` | ➖ | Fallback URL jika DB belum punya default device |
| `MIKROTIK_API_USER` | ➖ | Fallback username |
| `MIKROTIK_API_PASSWORD` | ➖ | Fallback password |
| `VIRUSTOTAL_API_KEY` | ⚠️ | VirusTotal API key |
| `ALIENVAULT_API_KEY` | ⚠️ | AlienVault OTX API key |
| `THREAT_FOX_API_KEY` | ⚠️ | ThreatFox API key |
| `NVD_API_KEY` | ⚠️ | NVD (NIST) CVE API key |
| `AUTO_BLOCK_ENABLED` | ➖ | `true`/`false`, default `true` |
| `THREAT_SCORE_THRESHOLD` | ➖ | Score minimum auto-block, default `5.0` |

> ✅ = wajib. ⚠️ = sangat direkomendasikan. ➖ = opsional.

---

## API Endpoints

### Auth
```
POST /auth/login          — Login → JWT token
GET  /auth/me             — Info user aktif
```

### Blocklist
```
GET  /blocklist/          — Daftar IP diblokir (skip/limit)
POST /blocklist/          — Block IP manual (auto geo+threat enrichment, upsert)
DEL  /blocklist/{ip}      — Unblock IP
POST /blocklist/sync      — Sync dari MikroTik
```

### Threats
```
GET  /threats/logs        — Log serangan (filter: status, attack_type, country, min_score)
GET  /threats/scan/{ip}   — Scan IP (VT + AlienVault + ThreatFox + GeoIP)
GET  /threats/cache/{ip}  — Hasil cache scan
GET  /threats/stats/summary — Summary stats
POST /threats/ingest      — Terima event syslog (internal, no-auth)
```

### Dashboard
```
GET  /dashboard/stats                      — Statistik utama
GET  /dashboard/attack-timeline            — Serangan per hari (N days)
GET  /dashboard/top-attackers              — Top IP penyerang
GET  /dashboard/mikrotik-status            — Status router default
GET  /dashboard/cve-alerts                 — CVE alerts (filter: severity, kev_only)
GET  /dashboard/geo-stats                  — Serangan per negara
GET  /dashboard/protocol-stats             — Attack types, protocol, target ports
GET  /dashboard/hourly-heatmap             — Distribusi per jam
GET  /dashboard/threat-score-distribution  — Distribusi skor ancaman
GET  /dashboard/summary-counts             — Ringkasan semua counter
POST /dashboard/cve-alerts/ingest          — Upsert CVE dari worker (internal, no-auth)
POST /dashboard/cleanup-expired            — Deactivate & unblock expired IPs
```

### MikroTik Monitor
> Semua endpoint mendukung `?device_id=<id>` untuk switch antar device.

```
GET   /mikrotik/interfaces              — Semua interface + traffic stats
GET   /mikrotik/firewall/rules          — Firewall filter rules (?chain=input|forward|output)
PATCH /mikrotik/firewall/rules/{id}/toggle — Enable/disable rule
GET   /mikrotik/firewall/nat            — NAT rules
GET   /mikrotik/firewall/address-lists  — Address lists
GET   /mikrotik/dhcp/leases             — DHCP leases (device terhubung)
GET   /mikrotik/connections             — Active connections (?limit=N)
GET   /mikrotik/logs                    — System logs (?count=N&topics=firewall)
GET   /mikrotik/routes                  — Routing table
GET   /mikrotik/addresses               — IP addresses per interface
GET   /mikrotik/identity                — Router hostname
```

### Whitelist
```
GET  /whitelist/          — Daftar whitelist
POST /whitelist/          — Tambah IP ke whitelist
DEL  /whitelist/{ip}      — Hapus dari whitelist
POST /whitelist/sync      — Push unsynced ke MikroTik + pull entries baru dari MikroTik
```

### Settings (Multi-Device)
```
GET  /settings/mikrotik                          — List semua device
POST /settings/mikrotik                          — Tambah device (auto-test + auto-setup FW)
GET  /settings/mikrotik/{id}                     — Detail satu device
PUT  /settings/mikrotik/{id}                     — Update device
DEL  /settings/mikrotik/{id}                     — Hapus device
POST /settings/mikrotik/{id}/test                — Test koneksi
POST /settings/mikrotik/{id}/set-default         — Set sebagai default
POST /settings/mikrotik/{id}/setup-firewall      — Buat DROP rules di device
POST /settings/mikrotik/setup-firewall/default   — Buat DROP rules di default device
POST /settings/mikrotik/refresh-all              — Refresh status semua device (concurrent)
GET  /settings/mikrotik/topology/view            — Data topology (nodes, status, stats)
```

---

## Hasil Functional Test

Dijalankan pada: **2026-03-24** | Environment: Docker Compose (local) | Router: MikroTik CCR1009-7G-1C-1S+ RouterOS 7.22

### Auth & Dashboard

| # | Test | Input | Result | Status |
|---|------|-------|--------|--------|
| 1 | Login JWT | `admin` / `admin1234` | Token JWT diterima | ✅ PASS |
| 2 | Dashboard Stats | `GET /dashboard/stats` | `mikrotik_connected: true` | ✅ PASS |
| 3 | MikroTik Status | `GET /dashboard/mikrotik-status` | CCR1009-7G-1C-1S+, Identity: heimdall | ✅ PASS |
| 4 | Startup load default device | Log `[Startup] Loaded default MikroTik device` | Loaded dari DB tanpa env vars | ✅ PASS |

### Threat Intelligence

| # | Test | IP | Expected | Result | Status |
|---|------|----|----------|--------|--------|
| 5 | Scan IP bersih | `8.8.8.8` | Score rendah, not malicious | Score: 0.04, Clean, ISP: Google LLC | ✅ PASS |
| 6 | Scan IP berbahaya | `185.220.101.1` | Score ≥ 5.0, malicious | Score: 5.24, `is_malicious: true` | ✅ PASS |
| 7 | GeoIP lengkap | `185.220.101.1` | Negara, ISP, koordinat | Germany DE, ISP: Stiftung Erneuerbare Freiheit | ✅ PASS |
| 8 | Cache threat scan | `185.220.101.1` (2nd call) | `cached: true` | Returned dari cache | ✅ PASS |
| 9 | Scoring VT·AV·TF | `185.220.101.1` | VT 40%·AV 45%·TF 15% | 1.86×0.40 + 10.0×0.45 + 0.0×0.15 = 5.24 | ✅ PASS |
| 10 | IP validation | `POST /blocklist/` address: `not-an-ip` | HTTP 422 validation error | `Value error, 'not-an-ip' is not a valid IP address` | ✅ PASS |

### Attack Pipeline

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 11 | Ingest syslog event | `POST /threats/ingest` ssh_brute dari `185.220.101.1` | Log terbuat, status: `analyzing` | ✅ PASS |
| 12 | Attack log terbuat | `GET /threats/logs` | 1 log, source_ip: `185.220.101.1` | ✅ PASS |
| 13 | Dashboard counter update | `GET /dashboard/stats` | `threats_detected` bertambah | ✅ PASS |

### Blocklist & Whitelist

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 14 | Block IP + geo enrichment | `POST /blocklist/` IP: `185.220.101.1` | Score: 5.24, Country: Germany, ISP lengkap, Synced: true | ✅ PASS |
| 15 | Re-block IP (upsert) | Block IP yang sudah di-unblock | Entry di-reactivate, tidak error UniqueViolation | ✅ PASS |
| 16 | Unblock IP | `DELETE /blocklist/185.220.101.1` | `{"message":"IP ... has been unblocked"}` | ✅ PASS |
| 17 | Tambah whitelist | `POST /whitelist/` IP: `192.168.1.100` | Tersimpan, `added_by: admin` | ✅ PASS |
| 18 | Sync whitelist ke MikroTik | `POST /whitelist/sync` | `pushed_to_mikrotik: 1`, `synced_to_mikrotik: true` | ✅ PASS |

### MikroTik Monitor

| # | Test | Endpoint | Result | Status |
|---|------|----------|--------|--------|
| 19 | Interfaces default | `GET /mikrotik/interfaces` | 11 interfaces (combo1, ether1...) | ✅ PASS |
| 20 | Interfaces per-device | `GET /mikrotik/interfaces?device_id=3` | 11 interfaces dari device spesifik | ✅ PASS |
| 21 | Firewall rules | `GET /mikrotik/firewall/rules` | SSTB-AutoBlock rules aktif | ✅ PASS |
| 22 | DHCP leases | `GET /mikrotik/dhcp/leases` | 12 device terhubung | ✅ PASS |
| 23 | System logs | `GET /mikrotik/logs` | Log entries MikroTik berhasil diambil | ✅ PASS |

### Settings, Firewall Setup & Topology

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 24 | Tambah device | `POST /settings/mikrotik` Router `192.168.100.3` | Device tersimpan, auto-test + auto-setup FW | ✅ PASS |
| 25 | Test koneksi | `POST /settings/mikrotik/{id}/test` | `connected: true`, Identity: heimdall | ✅ PASS |
| 26 | Setup firewall rules | `POST /settings/mikrotik/{id}/setup-firewall` | 3 rules created: Input, Forward, Forward-Dst | ✅ PASS |
| 27 | CVE ingest | `POST /dashboard/cve-alerts/ingest` CVE-2024-12345 | `{"status":"ok"}`, tersimpan di DB | ✅ PASS |
| 28 | Cleanup expired | `POST /dashboard/cleanup-expired` | `{"cleaned":0}` (tidak ada yang expired) | ✅ PASS |
| 29 | Topology data | `GET /settings/mikrotik/topology/view` | total: 1, online: 1, offline: 0 | ✅ PASS |
| 30 | Refresh all | `POST /settings/mikrotik/refresh-all` | 1 device dicek, status diperbarui | ✅ PASS |

### Ringkasan

```
Total Tests  : 30
PASS         : 30
FAIL         : 0
Success Rate : 100%
```

---

## Catatan Keamanan

- **SSL MikroTik**: `verify=False` untuk self-signed cert. Produksi: import sertifikat ke trusted store.
- **DB Password**: Hindari karakter `@` — merusak PostgreSQL connection string parsing.
- **Syslog & CVE ingest** tidak memerlukan auth — hanya diakses dari dalam Docker network. Jangan expose port 8080 ke internet.
- **API Password MikroTik** disimpan plaintext di DB internal. Untuk produksi, pertimbangkan enkripsi kolom (Fernet/AES).
- **SECRET_KEY** harus di-generate ulang untuk setiap deployment produksi.
- **`is_admin` default `False`** — user baru tidak punya akses admin sampai di-set manual.
- File `.env.local` dan `.env` di-gitignore.
- **RouterOS 7 REST API**: Gunakan `PUT` (bukan `POST`) untuk membuat entri address-list baru.

---

## Struktur Direktori

```
SSTB/
├── backend/
│   ├── main.py              — FastAPI app, lifespan (load default device), WebSocket
│   ├── mikrotik.py          — MikroTik REST API client (_get_client, multi-device, PUT)
│   ├── threat_intel.py      — VT, AlienVault, ThreatFox, GeoIP (scoring tanpa AbuseIPDB)
│   ├── models.py            — SQLAlchemy models (is_admin=False, BigInteger memory)
│   ├── schemas.py           — Pydantic schemas (IP validation, field_validator)
│   ├── config.py            — Settings (MIKROTIK vars opsional)
│   ├── auth.py              — JWT authentication
│   ├── database.py          — DB engine & session
│   └── routers/
│       ├── auth.py          — /auth
│       ├── blocklist.py     — /blocklist (geo enrichment, upsert, IP validation)
│       ├── threats.py       — /threats
│       ├── dashboard.py     — /dashboard (incl. cve-alerts/ingest, cleanup-expired)
│       ├── mikrotik_monitor.py — /mikrotik (semua endpoint support ?device_id)
│       ├── whitelist.py     — /whitelist (sync push+pull dua arah)
│       └── settings.py      — /settings (multi-device CRUD, setup-firewall, topology)
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── dashboard/page.tsx — 8 tab, device selector MikroTik Monitor, Setup FW button
│       │   └── login/page.tsx     — Halaman login
│       └── lib/
│           └── api.ts       — Axios client, semua API functions (incl. deviceId param)
├── worker/
│   └── tasks.py             — Celery tasks: ThreatFox, NVD, AlienVault, CISA KEV, cleanup
├── syslog/
│   └── syslog_receiver.py   — UDP 514 → /threats/ingest
├── docker-compose.yml
├── .env.example
└── .gitignore
```
