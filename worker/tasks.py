import os
import httpx
import asyncio
from celery import Celery
from celery.schedules import crontab
import logging

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8080")

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
THREAT_FOX_API_KEY = os.getenv("THREAT_FOX_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

app = Celery("sstb_worker", broker=REDIS_URL, backend=REDIS_URL)

app.conf.beat_schedule = {
    "sync-threatfox-daily": {
        "task": "tasks.sync_threatfox_database",
        "schedule": crontab(hour=2, minute=0),
    },
    "sync-nvd-cves-daily": {
        "task": "tasks.sync_nvd_cves",
        "schedule": crontab(hour=3, minute=0),
    },
    "sync-alienvault-daily": {
        "task": "tasks.sync_alienvault_pulses",
        "schedule": crontab(hour=4, minute=0),
    },
    "sync-cisa-kev-daily": {
        "task": "tasks.sync_cisa_kev",
        "schedule": crontab(hour=5, minute=0),
    },
    "cleanup-expired-blocks-hourly": {
        "task": "tasks.cleanup_expired_blocks",
        "schedule": crontab(minute=0),  # every hour on the hour
    },
}
app.conf.timezone = "UTC"


def run_async(coro):
    """Helper to run async functions in Celery tasks."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Deep IP Analysis ──────────────────────────────────────────────────────────

@app.task(name="tasks.analyze_ip_deep", bind=True, max_retries=3)
def analyze_ip_deep(self, ip: str):
    """Deep analysis of a single IP using all threat intelligence sources."""
    logger.info(f"[Worker] Deep analysis for IP: {ip}")
    try:
        result = run_async(_analyze_ip_deep(ip))
        return result
    except Exception as exc:
        logger.error(f"[Worker] Error analyzing {ip}: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _analyze_ip_deep(ip: str) -> dict:
    vt_score = 0.0
    av_score = 0.0
    tf_score = 0.0

    async with httpx.AsyncClient(timeout=20.0) as client:
        if VIRUSTOTAL_API_KEY:
            try:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    vt_score = min((malicious / total) * 10, 10.0)
            except Exception as e:
                logger.error(f"VT error: {e}")

        if ALIENVAULT_API_KEY:
            try:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    pulses = data.get("pulse_info", {}).get("count", 0)
                    av_score = min(pulses * 2.0, 10.0)
            except Exception as e:
                logger.error(f"AlienVault error: {e}")

        if THREAT_FOX_API_KEY:
            try:
                resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": ip},
                    headers={"API-KEY": THREAT_FOX_API_KEY},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        iocs = data.get("data", [])
                        tf_score = min(len(iocs) * 3.0, 10.0)
            except Exception as e:
                logger.error(f"ThreatFox error: {e}")

    total_score = (vt_score * 0.40) + (av_score * 0.45) + (tf_score * 0.15)
    return {
        "ip": ip,
        "threat_score": round(total_score, 2),
        "is_malicious": total_score >= 5.0,
        "virustotal_score": vt_score,
        "alienvault_score": av_score,
        "threatfox_score": tf_score,
    }


# ── ThreatFox Sync ────────────────────────────────────────────────────────────

@app.task(name="tasks.sync_threatfox_database", bind=True)
def sync_threatfox_database(self):
    """Sync recent ThreatFox IoCs to local database via backend ingest."""
    logger.info("[Worker] Syncing ThreatFox database...")
    try:
        result = run_async(_sync_threatfox())
        return {"synced": result}
    except Exception as e:
        logger.error(f"[Worker] ThreatFox sync failed: {e}")


async def _sync_threatfox() -> int:
    if not THREAT_FOX_API_KEY:
        return 0

    synced = 0
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            headers={"API-KEY": THREAT_FOX_API_KEY},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                for ioc in data.get("data", []):
                    if ioc.get("ioc_type") == "ip:port":
                        ip = ioc.get("ioc", "").split(":")[0]
                        if ip:
                            try:
                                await client.post(
                                    f"{BACKEND_URL}/threats/ingest",
                                    json={
                                        "source_ip": ip,
                                        "attack_type": "threatfox_sync",
                                        "raw_log": f"ThreatFox IoC: {ioc.get('tags', [])}",
                                    },
                                    timeout=5.0,
                                )
                                synced += 1
                            except Exception:
                                pass
    return synced


# ── NVD CVE Sync ──────────────────────────────────────────────────────────────

@app.task(name="tasks.sync_nvd_cves", bind=True)
def sync_nvd_cves(self):
    """Fetch and store MikroTik-related CVEs from NVD into the backend."""
    logger.info("[Worker] Syncing NVD CVEs...")
    try:
        result = run_async(_sync_nvd_cves())
        return result
    except Exception as e:
        logger.error(f"[Worker] NVD sync failed: {e}")
        return {"synced": 0, "error": str(e)}


async def _sync_nvd_cves() -> dict:
    if not NVD_API_KEY:
        logger.warning("[Worker] NVD_API_KEY not set, skipping CVE sync")
        return {"synced": 0, "skipped": "no NVD_API_KEY"}

    synced = 0
    failed = 0
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": "MikroTik RouterOS", "resultsPerPage": 50},
                headers={"apiKey": NVD_API_KEY},
            )
            if resp.status_code != 200:
                return {"synced": 0, "error": f"NVD HTTP {resp.status_code}"}

            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # CVSS score — try v3.1 then v3.0 then v2
                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                severity = "MEDIUM"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        cvss_data = entries[0].get("cvssData", {})
                        cvss_score = float(cvss_data.get("baseScore", 0.0))
                        severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "MEDIUM")).upper()
                        break

                description = ""
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                published = cve.get("published", "")
                affected = "MikroTik RouterOS"

                try:
                    await client.post(
                        f"{BACKEND_URL}/dashboard/cve-alerts/ingest",
                        json={
                            "cve_id": cve_id,
                            "description": description,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "published_date": published,
                            "affected_product": affected,
                            "is_kev": False,
                        },
                        timeout=5.0,
                    )
                    synced += 1
                except Exception as e:
                    logger.error(f"[Worker] Failed to ingest {cve_id}: {e}")
                    failed += 1

        except Exception as e:
            return {"synced": 0, "error": str(e)}

    logger.info(f"[Worker] NVD CVE sync: {synced} stored, {failed} failed")
    return {"synced": synced, "failed": failed}


# ── AlienVault Pulse Sync ─────────────────────────────────────────────────────

@app.task(name="tasks.sync_alienvault_pulses", bind=True)
def sync_alienvault_pulses(self):
    """Sync AlienVault OTX pulses — feed IPs from network-related pulses into ingest."""
    logger.info("[Worker] Syncing AlienVault pulses...")
    try:
        result = run_async(_sync_alienvault_pulses())
        return result
    except Exception as e:
        logger.error(f"[Worker] AlienVault sync failed: {e}")
        return {"synced": 0, "error": str(e)}


async def _sync_alienvault_pulses() -> dict:
    if not ALIENVAULT_API_KEY:
        logger.warning("[Worker] ALIENVAULT_API_KEY not set, skipping pulse sync")
        return {"synced": 0, "skipped": "no ALIENVAULT_API_KEY"}

    synced = 0
    failed = 0
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Fetch recent subscribed pulses (last 7 days)
            resp = await client.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY},
                params={"modified_since": "", "limit": 20},
            )
            if resp.status_code != 200:
                return {"synced": 0, "error": f"OTX HTTP {resp.status_code}"}

            pulses = resp.json().get("results", [])
            seen_ips: set = set()

            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") == "IPv4":
                        ip = indicator.get("indicator", "")
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            try:
                                await client.post(
                                    f"{BACKEND_URL}/threats/ingest",
                                    json={
                                        "source_ip": ip,
                                        "attack_type": "alienvault_pulse",
                                        "raw_log": f"OTX Pulse: {pulse.get('name', '')}",
                                    },
                                    timeout=5.0,
                                )
                                synced += 1
                            except Exception:
                                failed += 1
        except Exception as e:
            return {"synced": 0, "error": str(e)}

    logger.info(f"[Worker] AlienVault pulse sync: {synced} IPs ingested, {failed} failed")
    return {"synced": synced, "failed": failed}


# ── CISA KEV Sync ─────────────────────────────────────────────────────────────

@app.task(name="tasks.sync_cisa_kev", bind=True)
def sync_cisa_kev(self):
    """Fetch CISA Known Exploited Vulnerabilities and store MikroTik-related entries."""
    logger.info("[Worker] Syncing CISA KEV catalog...")
    try:
        result = run_async(_sync_cisa_kev())
        return result
    except Exception as e:
        logger.error(f"[Worker] CISA KEV sync failed: {e}")
        return {"synced": 0, "error": str(e)}


async def _sync_cisa_kev() -> dict:
    keywords = {"mikrotik", "routeros", "winbox", "router", "firewall", "network"}
    synced = 0
    total = 0

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(CISA_KEV_URL)
            if resp.status_code != 200:
                return {"synced": 0, "error": f"HTTP {resp.status_code}"}

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total = len(vulnerabilities)

            for vuln in vulnerabilities:
                product = vuln.get("product", "").lower()
                vendor = vuln.get("vendorProject", "").lower()
                description = vuln.get("shortDescription", "").lower()
                text = f"{product} {vendor} {description}"

                if any(kw in text for kw in keywords):
                    try:
                        await client.post(
                            f"{BACKEND_URL}/dashboard/cve-alerts/ingest",
                            json={
                                "cve_id": vuln.get("cveID", ""),
                                "description": vuln.get("shortDescription", ""),
                                "severity": "CRITICAL",
                                "cvss_score": 9.0,
                                "published_date": vuln.get("dateAdded", ""),
                                "affected_product": f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}",
                                "is_kev": True,
                            },
                            timeout=5.0,
                        )
                        synced += 1
                    except Exception:
                        pass
        except Exception as e:
            return {"synced": 0, "error": str(e)}

    logger.info(f"[Worker] CISA KEV: {synced} MikroTik-related entries out of {total} total")
    return {"synced": synced, "total_kev": total}


# ── Cleanup Expired Blocks ────────────────────────────────────────────────────

@app.task(name="tasks.cleanup_expired_blocks", bind=True)
def cleanup_expired_blocks(self):
    """Deactivate expired blocked IPs by calling backend cleanup endpoint."""
    logger.info("[Worker] Cleaning up expired blocked IPs...")
    try:
        result = run_async(_cleanup_expired())
        return result
    except Exception as e:
        logger.error(f"[Worker] Cleanup failed: {e}")
        return {"cleaned": 0, "error": str(e)}


async def _cleanup_expired() -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Need auth — use internal service token if set, else skip
            secret = os.getenv("WORKER_SECRET", os.getenv("SECRET_KEY", ""))
            if not secret:
                return {"cleaned": 0, "skipped": "no WORKER_SECRET or SECRET_KEY"}

            # Get token
            login_resp = await client.post(
                f"{BACKEND_URL}/auth/login",
                json={"username": os.getenv("WORKER_USER", "admin"),
                      "password": os.getenv("WORKER_PASSWORD", "")},
                timeout=10.0,
            )
            if login_resp.status_code != 200:
                return {"cleaned": 0, "error": "login failed"}

            token = login_resp.json().get("access_token", "")
            resp = await client.post(
                f"{BACKEND_URL}/dashboard/cleanup-expired",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0,
            )
            if resp.status_code == 200:
                return resp.json()
            return {"cleaned": 0, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"cleaned": 0, "error": str(e)}
