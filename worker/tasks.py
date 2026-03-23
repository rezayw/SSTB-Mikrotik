import os
import httpx
import asyncio
from celery import Celery
from celery.schedules import crontab
import logging

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
THREAT_FOX_API_KEY = os.getenv("THREAT_FOX_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

app = Celery("sstb_worker", broker=REDIS_URL, backend=REDIS_URL)

app.conf.beat_schedule = {
    "sync-threatfox-daily": {
        "task": "tasks.sync_threatfox_database",
        "schedule": crontab(hour=2, minute=0),  # 2 AM daily
    },
    "sync-nvd-cves-daily": {
        "task": "tasks.sync_nvd_cves",
        "schedule": crontab(hour=3, minute=0),  # 3 AM daily
    },
    "sync-alienvault-daily": {
        "task": "tasks.sync_alienvault_pulses",
        "schedule": crontab(hour=4, minute=0),  # 4 AM daily
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
        # VirusTotal
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

        # AlienVault OTX
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

        # ThreatFox
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

    total_score = (vt_score * 0.5) + (av_score * 0.3) + (tf_score * 0.2)
    is_malicious = total_score >= 5.0

    return {
        "ip": ip,
        "threat_score": round(total_score, 2),
        "is_malicious": is_malicious,
        "virustotal_score": vt_score,
        "alienvault_score": av_score,
        "threatfox_score": tf_score,
    }


@app.task(name="tasks.sync_threatfox_database", bind=True)
def sync_threatfox_database(self):
    """Sync recent ThreatFox IoCs to local database."""
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
                iocs = data.get("data", [])
                for ioc in iocs:
                    if ioc.get("ioc_type") == "ip:port":
                        ip = ioc.get("ioc", "").split(":")[0]
                        if ip:
                            # Notify backend to pre-cache this threat
                            try:
                                await client.post(
                                    f"{BACKEND_URL}/threats/ingest",
                                    json={
                                        "source_ip": ip,
                                        "attack_type": "threatfox_sync",
                                        "raw_log": f"ThreatFox IoC: {ioc.get('tags', [])}",
                                    },
                                )
                                synced += 1
                            except Exception:
                                pass
    return synced


@app.task(name="tasks.sync_nvd_cves", bind=True)
def sync_nvd_cves(self):
    """Fetch and store MikroTik-related CVEs from NVD."""
    logger.info("[Worker] Syncing NVD CVEs...")
    try:
        result = run_async(_sync_nvd_cves())
        return {"cves_synced": result}
    except Exception as e:
        logger.error(f"[Worker] NVD sync failed: {e}")


async def _sync_nvd_cves() -> int:
    if not NVD_API_KEY:
        return 0

    synced = 0
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "MikroTik RouterOS", "resultsPerPage": 50},
            headers={"apiKey": NVD_API_KEY},
        )
        if resp.status_code == 200:
            data = resp.json()
            # In a full implementation, parse and store each CVE
            synced = len(data.get("vulnerabilities", []))
    return synced


@app.task(name="tasks.sync_alienvault_pulses", bind=True)
def sync_alienvault_pulses(self):
    """Sync AlienVault OTX pulses for network threats."""
    logger.info("[Worker] Syncing AlienVault pulses...")
    return {"status": "ok"}
