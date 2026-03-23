# SSTB — Smart Security & Threat Blocker

Sistem keamanan proaktif untuk MikroTik RouterOS yang mengintegrasikan threat intelligence eksternal (VirusTotal, AlienVault OTX, ThreatFox, CISA KEV/NVD) untuk mendeteksi dan memblokir IP berbahaya secara otomatis.

## Arsitektur

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Compose                      │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │ Frontend │    │ Backend  │    │     Worker       │   │
│  │ Next.js  │◄──►│ FastAPI  │◄──►│ Celery + Redis   │   │
│  │ :3000    │    │ :8080    │    │ (background jobs)│   │
│  └──────────┘    └────┬─────┘    └──────────────────┘   │
│                       │                                 │
│  ┌──────────┐    ┌────▼─────┐    ┌──────────────────┐   │
│  │  Syslog  │───►│PostgreSQL│    │      Redis       │   │
│  │ UDP :514 │    │   DB     │    │   (broker/cache) │   │
│  └──────────┘    └──────────┘    └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ▲                              ▼
   MikroTik Syslog              MikroTik REST API
   (log firewall)            (block/unblock IP via
                              Address List firewall)
```

## Alur Kerja

1. **Deteksi** — MikroTik mengirim log firewall via Syslog (UDP 514) ke container syslog receiver
2. **Analisis Lokal** — Backend cek database lokal (ThreatFox cache, CISA KEV)
3. **Analisis Eksternal** — Worker (Celery) query VirusTotal + AlienVault + ThreatFox secara paralel
4. **Auto-Block** — Jika threat score ≥ 5.0, backend langsung push ke MikroTik via REST API → masuk Address List `SSTB-Blacklist`
5. **Dashboard** — Admin memantau real-time: blocked IPs, attack timeline, CVE alerts, router status

## Persyaratan

- Docker & Docker Compose v2+
- MikroTik RouterOS dengan REST API aktif
- API keys: VirusTotal, AlienVault OTX, ThreatFox, URLScan (opsional), NVD

## Instalasi

### 1. Clone & Konfigurasi

```bash
git clone https://github.com/rezayw/SSTB.git
cd SSTB
cp .env.example .env.local
```

Edit `.env.local` dengan kredensial Anda:

```env
SECRET_KEY=<generate: python3 -c "import secrets; print(secrets.token_hex(32))">
DB_PASSWORD=ganti-dengan-password-kuat
MIKROTIK_API_URL=https://192.168.X.X/
MIKROTIK_API_USER=api-user
MIKROTIK_API_PASSWORD=password-mikrotik
VIRUSTOTAL_API_KEY=...
ALIENVAULT_API_KEY=...
THREAT_FOX_API_KEY=...
```

### 2. Build & Jalankan

```bash
docker compose build
docker compose up -d
```

### 3. Seed Admin

```bash
docker compose exec backend python -c "
from database import SessionLocal
from models import User
from auth import hash_password

db = SessionLocal()
user = User(
    email='admin@sstb.local',
    username='admin',
    hashed_password=hash_password('ganti-password-anda'),
    is_active=True,
    is_admin=True,
)
db.add(user)
db.commit()
print('Admin created!')
"
```

### 4. Akses Dashboard

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:8080 |
| API Docs | http://localhost:8080/docs |

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

### Aktifkan Syslog ke Server SSTB

```routeros
/system logging action add name=sstb-syslog target=remote remote=<IP-SERVER-SSTB> remote-port=514 bsd-syslog=yes
/system logging add action=sstb-syslog topics=firewall
```

### Buat Firewall Rule Drop untuk SSTB-Blacklist

```routeros
/ip firewall filter add chain=input src-address-list=SSTB-Blacklist action=drop comment="SSTB Auto-Block" place-before=0
/ip firewall filter add chain=forward src-address-list=SSTB-Blacklist action=drop comment="SSTB Auto-Block Forward" place-before=1
```

## Variabel Environment

Semua variabel wajib ada di `.env.local` (lihat `.env.example`):

| Variabel | Keterangan |
|---|---|
| `SECRET_KEY` | JWT signing key, min. 32 karakter |
| `DB_USER` | PostgreSQL username |
| `DB_PASSWORD` | PostgreSQL password |
| `DB_NAME` | Nama database |
| `MIKROTIK_API_URL` | URL REST API MikroTik (HTTPS) |
| `MIKROTIK_API_USER` | MikroTik API username |
| `MIKROTIK_API_PASSWORD` | MikroTik API password |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `ALIENVAULT_API_KEY` | AlienVault OTX API key |
| `THREAT_FOX_API_KEY` | ThreatFox API key |
| `NVD_API_KEY` | NVD (NIST) API key |
| `URLSCAN_API_KEY` | URLScan.io API key |

## API Endpoints

```
POST /auth/login        — Login, returns JWT
POST /auth/register     — Register admin
GET  /auth/me           — Info user aktif

GET  /blocklist/        — Daftar IP yang diblokir
POST /blocklist/        — Block IP manual
DEL  /blocklist/{ip}    — Unblock IP
POST /blocklist/sync    — Sinkronisasi dari MikroTik

GET  /threats/logs      — Log serangan
GET  /threats/scan/{ip} — Scan IP via threat intelligence
POST /threats/ingest    — Terima event dari syslog (internal)

GET  /dashboard/stats          — Statistik dashboard
GET  /dashboard/attack-timeline — Chart serangan per hari
GET  /dashboard/top-attackers  — Top IP penyerang
GET  /dashboard/mikrotik-status — Status router
GET  /dashboard/cve-alerts     — CVE alerts MikroTik
```

## Catatan Keamanan

- **SSL MikroTik**: `verify=False` digunakan karena MikroTik menggunakan self-signed certificate. Untuk produksi, import sertifikat MikroTik ke trusted store.
- **Syslog endpoint** (`/threats/ingest`) tidak memerlukan auth karena hanya dapat diakses dari dalam Docker network. Jangan expose port 8080 ke publik tanpa firewall.
- **SECRET_KEY** harus di-generate ulang untuk setiap deployment produksi.

## Lisensi

MIT
