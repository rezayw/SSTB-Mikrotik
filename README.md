# SSTB — Smart Security & Threat Blocker

> Advanced Multi-MikroTik Security Platform

Sistem keamanan proaktif untuk MikroTik RouterOS yang mengintegrasikan threat intelligence eksternal (VirusTotal, AlienVault OTX, ThreatFox, CISA KEV/NVD) dengan geolokasi IP, deteksi otomatis, dan manajemen multi-router dari satu dashboard.

---
## NOTE SARAN
DEPLOY APLIKASI INI DI LINGKUNGAN TERISOLASI (INTRANET) UNTUK MENGHINDARI POTENSI PENYALAHGUNAAN API KEY THREAT INTEL.

## Arsitektur

```
┌──────────────────────────────────────────────────────────────┐
│                        Docker Compose                        │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐  │
│  │ Frontend │    │ Backend  │    │        Worker          │  │
│  │ Next.js  │◄──►│ FastAPI  │◄──►│  Celery + Redis        │  │
│  │  :3000   │    │  :8080   │    │  (ThreatFox / NVD /    │  │
│  └──────────┘    └────┬─────┘    │   CISA KEV sync)       │  │
│                       │          └────────────────────────┘  │
│  ┌──────────┐    ┌────▼─────┐    ┌────────────────────────┐  │
│  │  Syslog  │───►│PostgreSQL│    │        Redis           │  │
│  │ UDP :514 │    │    DB    │    │   (broker / cache)     │  │
│  └──────────┘    └──────────┘    └────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
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
| **NVD** | CVE MikroTik RouterOS |

**Scoring:** VT 40% · AlienVault 45% · ThreatFox 15%
**Threshold:** Score ≥ 5.0 → `is_malicious: true`

> AbuseIPDB tidak diikutsertakan dalam scoring karena tanpa API key nilainya selalu 0.0 yang menurunkan total skor IP berbahaya secara signifikan.

### Multi-MikroTik Management
- Tambah/edit/hapus beberapa router MikroTik dari satu panel Settings
- Test koneksi per-device dengan informasi model, versi, uptime, CPU, memori
- Set router default untuk auto-block
- Topology SVG real-time: status online/offline, animasi koneksi aktif

### Dashboard (8 Tab)
- **Overview** — Stats, Attack Timeline, Hourly Heatmap, Top Attackers
- **IP Blocklist** — Kelola IP yang diblokir, scan TI, filter (dengan geo enrichment otomatis)
- **Attack Logs** — Log serangan dengan filter status/tipe/negara/score
- **CVE Alerts** — CVE MikroTik, KEV filter, CVSS score
- **MikroTik Monitor** — Interfaces, Firewall Rules (toggle), NAT, DHCP, Connections, System Logs
- **Geo Analytics** — Top negara penyerang, protocol breakdown, distribusi threat score
- **Whitelist** — Manajemen IP whitelist + sync ke MikroTik
- **Settings** — Multi-device config + Topology diagram

### Real-time
- WebSocket live feed serangan masuk
- Ping/pong keep-alive setiap 20 detik

### Geo Enrichment Otomatis
- Saat Block IP manual: otomatis lookup GeoIP + threat scan sebelum disimpan
- Country, City, ISP, ASN, threat_score, is_proxy, is_tor langsung terisi
- Jika IP sudah pernah di-unblock: entry di-reactivate (tidak duplikat)

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
        │       └── Simpan ke DB + push ke MikroTik SSTB-Blacklist
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

Edit `.env.local`:

```env
SECRET_KEY=<python3 -c "import secrets; print(secrets.token_hex(32))">
DB_USER=sstb
DB_PASSWORD=password-kuat-tanpa-karakter-khusus
DB_NAME=sstb

MIKROTIK_API_URL=https://192.168.X.X/
MIKROTIK_API_USER=sstb-api
MIKROTIK_API_PASSWORD=password-mikrotik

VIRUSTOTAL_API_KEY=...
ALIENVAULT_API_KEY=...
THREAT_FOX_API_KEY=...
NVD_API_KEY=...
```

> **Penting:** `DB_PASSWORD` tidak boleh mengandung karakter `@` karena akan merusak DATABASE_URL (PostgreSQL connection string parsing).

### 2. Build & Jalankan

```bash
docker compose --env-file .env.local build
docker compose --env-file .env.local up -d
```

### 3. Seed Admin

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

Buka **Settings** tab di dashboard → klik **+ Add Device** → isi:
- Name, Host/IP, Port (443), API User, API Password
- Centang "Use SSL" dan "Set as Default"
- Klik **Add & Test Connection** — status langsung tampil

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

### Firewall Drop Rules

```routeros
/ip firewall filter add chain=input src-address-list=SSTB-Blacklist \
  action=drop comment="SSTB Auto-Block" place-before=0
/ip firewall filter add chain=forward src-address-list=SSTB-Blacklist \
  action=drop comment="SSTB Auto-Block Forward" place-before=1
```

> **Catatan RouterOS 7:** MikroTik REST API menggunakan `PUT` (bukan `POST`) untuk membuat entri address-list baru. SSTB sudah mengimplementasikan ini dengan benar.

---

## Variabel Environment

| Variabel | Wajib | Keterangan |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key, min. 32 karakter |
| `DB_USER` | ✅ | PostgreSQL username |
| `DB_PASSWORD` | ✅ | PostgreSQL password (tanpa karakter `@`) |
| `DB_NAME` | ✅ | Nama database |
| `MIKROTIK_API_URL` | ✅ | URL REST API router default (HTTPS) |
| `MIKROTIK_API_USER` | ✅ | MikroTik API username |
| `MIKROTIK_API_PASSWORD` | ✅ | MikroTik API password |
| `VIRUSTOTAL_API_KEY` | ⚠️ | VirusTotal API key |
| `ALIENVAULT_API_KEY` | ⚠️ | AlienVault OTX API key |
| `THREAT_FOX_API_KEY` | ⚠️ | ThreatFox API key |
| `NVD_API_KEY` | ⚠️ | NVD (NIST) CVE API key |
| `AUTO_BLOCK_ENABLED` | ➖ | `true`/`false`, default `true` |
| `THREAT_SCORE_THRESHOLD` | ➖ | Score minimum auto-block, default `5.0` |

> ⚠️ = sangat direkomendasikan. ➖ = opsional.

---

## API Endpoints

### Auth
```
POST /auth/login          — Login → JWT token
POST /auth/register       — Daftar user baru
GET  /auth/me             — Info user aktif
```

### Blocklist
```
GET  /blocklist/          — Daftar IP diblokir (skip/limit)
POST /blocklist/          — Block IP manual (auto geo+threat enrichment)
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
```

### MikroTik Monitor
```
GET   /mikrotik/interfaces              — Semua interface + traffic stats
GET   /mikrotik/firewall/rules          — Firewall filter rules
PATCH /mikrotik/firewall/rules/{id}/toggle — Enable/disable rule
GET   /mikrotik/firewall/nat            — NAT rules
GET   /mikrotik/firewall/address-lists  — Address lists
GET   /mikrotik/dhcp/leases             — DHCP leases (device terhubung)
GET   /mikrotik/connections             — Active connections
GET   /mikrotik/logs                    — System logs
GET   /mikrotik/routes                  — Routing table
GET   /mikrotik/addresses               — IP addresses per interface
GET   /mikrotik/identity                — Router hostname
```

### Whitelist
```
GET  /whitelist/          — Daftar whitelist
POST /whitelist/          — Tambah IP ke whitelist
DEL  /whitelist/{ip}      — Hapus dari whitelist
POST /whitelist/sync      — Push unsynced ke MikroTik + pull dari MikroTik
```

### Settings (Multi-Device)
```
GET  /settings/mikrotik                     — List semua device
POST /settings/mikrotik                     — Tambah device baru (auto-test)
GET  /settings/mikrotik/{id}                — Detail satu device
PUT  /settings/mikrotik/{id}                — Update device
DEL  /settings/mikrotik/{id}                — Hapus device
POST /settings/mikrotik/{id}/test           — Test koneksi
POST /settings/mikrotik/{id}/set-default    — Set sebagai default
POST /settings/mikrotik/refresh-all         — Refresh status semua device
GET  /settings/mikrotik/topology/view       — Data topology
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

### Threat Intelligence

| # | Test | IP | Expected | Result | Status |
|---|------|----|----------|--------|--------|
| 4 | Scan IP bersih | `8.8.8.8` | Score rendah, not malicious | Score: 0.04, Clean, ISP: Google LLC | ✅ PASS |
| 5 | Scan IP berbahaya | `185.220.101.1` | Score ≥ 5.0, malicious | Score: 5.24, `is_malicious: true` | ✅ PASS |
| 6 | GeoIP lengkap | `185.220.101.1` | Negara, ISP, koordinat | Germany DE, ISP: Stiftung Erneuerbare Freiheit, Lat: 52.617 | ✅ PASS |
| 7 | Cache threat scan | `185.220.101.1` (2nd call) | `cached: true` | Returned dari cache | ✅ PASS |
| 8 | Scoring tanpa AbuseIPDB | `185.220.101.1` | VT 40%·AV 45%·TF 15% | VT: 1.86 · AV: 10.0 · TF: 0.0 → 5.24 | ✅ PASS |

### Attack Pipeline

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 9 | Ingest syslog event | `POST /threats/ingest` ssh_brute dari `185.220.101.1` | Log terbuat, status: `analyzing` | ✅ PASS |
| 10 | Attack log terbuat | `GET /threats/logs` | 1 log, source_ip: `185.220.101.1`, attack_type: `ssh_brute` | ✅ PASS |
| 11 | Dashboard counter update | `GET /dashboard/stats` | `threats_detected` bertambah | ✅ PASS |

### Blocklist & Whitelist

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 12 | Block IP manual + geo enrichment | `POST /blocklist/` IP: `185.220.101.1` | Score: 5.24, Country: Germany, ISP: Stiftung Erneuerbare Freiheit, Synced: true | ✅ PASS |
| 13 | Re-block IP (upsert) | Block IP yang sudah pernah di-unblock | Entry di-reactivate, tidak error UniqueViolation | ✅ PASS |
| 14 | Unblock IP | `DELETE /blocklist/185.220.101.1` | `{"message":"IP ... has been unblocked"}` | ✅ PASS |
| 15 | Tambah whitelist | `POST /whitelist/` IP: `192.168.1.100` | Tersimpan, `added_by: admin` | ✅ PASS |
| 16 | Sync whitelist ke MikroTik | `POST /whitelist/sync` | `pushed_to_mikrotik: 1`, entry `synced_to_mikrotik: true` | ✅ PASS |

### MikroTik Monitor

| # | Test | Endpoint | Result | Status |
|---|------|----------|--------|--------|
| 17 | Interfaces | `GET /mikrotik/interfaces` | 11 interfaces (ether1 running, combo1 down) | ✅ PASS |
| 18 | Firewall rules | `GET /mikrotik/firewall/rules` | SSTB-Blacklist drop rules aktif | ✅ PASS |
| 19 | DHCP leases | `GET /mikrotik/dhcp/leases` | 12 device terhubung | ✅ PASS |
| 20 | System logs | `GET /mikrotik/logs` | Log entries MikroTik berhasil diambil | ✅ PASS |

### Settings & Topology (Multi-Device)

| # | Test | Action | Result | Status |
|---|------|--------|--------|--------|
| 21 | Tambah device | `POST /settings/mikrotik` Router `192.168.100.3` | Device tersimpan, auto-test berhasil | ✅ PASS |
| 22 | Test koneksi | `POST /settings/mikrotik/{id}/test` | `connected: true`, Identity: heimdall, Model: CCR1009-7G-1C-1S+ | ✅ PASS |
| 23 | Topology data | `GET /settings/mikrotik/topology/view` | total: 1, online: 1, offline: 0 | ✅ PASS |
| 24 | Refresh all | `POST /settings/mikrotik/refresh-all` | 1 device dicek, status diperbarui | ✅ PASS |

### Ringkasan

```
Total Tests  : 24
PASS         : 24
FAIL         : 0
Success Rate : 100%
```

---

## Catatan Keamanan

- **SSL MikroTik**: `verify=False` digunakan karena MikroTik self-signed cert. Untuk produksi, import sertifikat ke trusted store.
- **DB Password**: Jangan gunakan karakter `@` dalam `DB_PASSWORD` karena akan merusak DATABASE_URL (PostgreSQL connection string parsing).
- **Syslog endpoint** (`/threats/ingest`) tidak memerlukan auth — hanya dapat diakses dari dalam Docker network. Jangan expose port 8080 ke internet.
- **API Password MikroTik** disimpan plaintext di database internal. DB hanya diakses dari Docker network. Untuk produksi, pertimbangkan enkripsi kolom dengan Fernet/AES.
- **SECRET_KEY** harus di-generate ulang untuk setiap deployment produksi.
- File `.env.local` dan `.env` sudah di-gitignore.
- **RouterOS 7 REST API**: Gunakan `PUT` (bukan `POST`) untuk membuat entri address-list baru. `POST` mengembalikan `400 "no such command"`.

---

## Struktur Direktori

```
SSTB/
├── backend/
│   ├── main.py              — FastAPI app, WebSocket feed
│   ├── mikrotik.py          — MikroTik REST API client (multi-device, PUT fix)
│   ├── threat_intel.py      — VT, AlienVault, ThreatFox, GeoIP (AbuseIPDB dihapus dari scoring)
│   ├── models.py            — SQLAlchemy models (incl. MikroTikDevice, BigInteger)
│   ├── schemas.py           — Pydantic schemas
│   ├── config.py            — Settings dari env vars
│   ├── auth.py              — JWT authentication
│   ├── database.py          — DB engine & session
│   └── routers/
│       ├── auth.py          — /auth
│       ├── blocklist.py     — /blocklist (geo enrichment + upsert)
│       ├── threats.py       — /threats
│       ├── dashboard.py     — /dashboard
│       ├── mikrotik_monitor.py — /mikrotik
│       ├── whitelist.py     — /whitelist (sync push+pull)
│       └── settings.py      — /settings (multi-device + topology)
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── dashboard/page.tsx — Dashboard utama (8 tab, tanpa AbuseIPDB)
│       │   └── login/page.tsx     — Halaman login
│       └── lib/
│           └── api.ts       — Axios client + semua API functions
├── worker/
│   └── tasks.py             — Celery tasks (ThreatFox, NVD, CISA KEV sync)
├── syslog/
│   └── syslog_receiver.py   — UDP 514 → /threats/ingest
├── docker-compose.yml
├── .env.example
└── .gitignore
```
