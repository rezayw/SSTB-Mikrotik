import httpx
import json
import logging
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)


async def check_virustotal(ip: str) -> dict:
    """Check IP against VirusTotal."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                score = ((malicious * 1.0 + suspicious * 0.5) / total) * 10
                return {
                    "score": round(min(score, 10.0), 2),
                    "detected": malicious > 0,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "details": stats,
                }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[VirusTotal] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_alienvault(ip: str) -> dict:
    """Check IP against AlienVault OTX."""
    if not settings.ALIENVAULT_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                score = min(pulse_count * 2.0, 10.0)
                return {
                    "score": round(score, 2),
                    "detected": pulse_count > 0,
                    "pulse_count": pulse_count,
                    "details": {"pulses": pulse_count},
                }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[AlienVault] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_threatfox(ip: str) -> dict:
    """Check IP against ThreatFox."""
    if not settings.THREAT_FOX_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"API-KEY": settings.THREAT_FOX_API_KEY}
    payload = {"query": "search_ioc", "search_term": ip}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload,
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    iocs = data.get("data", [])
                    score = min(len(iocs) * 3.0, 10.0)
                    return {
                        "score": round(score, 2),
                        "detected": len(iocs) > 0,
                        "ioc_count": len(iocs),
                        "details": {"iocs_found": len(iocs)},
                    }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[ThreatFox] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_urlscan(url: str) -> dict:
    """Submit URL to URLScan for analysis."""
    if not settings.URLSCAN_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {
        "API-Key": settings.URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {"url": url, "visibility": "private"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://urlscan.io/api/v1/scan/",
                json=payload,
                headers=headers,
            )
            if response.status_code in (200, 201):
                data = response.json()
                return {
                    "score": 5.0,
                    "detected": True,
                    "scan_id": data.get("uuid"),
                    "details": data,
                }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[URLScan] Error scanning {url}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def analyze_ip(ip: str) -> dict:
    """Run full threat intelligence analysis on an IP."""
    import asyncio
    vt, av, tf = await asyncio.gather(
        check_virustotal(ip),
        check_alienvault(ip),
        check_threatfox(ip),
    )

    vt_score = vt.get("score", 0.0)
    av_score = av.get("score", 0.0)
    tf_score = tf.get("score", 0.0)

    # Weighted average: VT 50%, AV 30%, TF 20%
    total_score = (vt_score * 0.5) + (av_score * 0.3) + (tf_score * 0.2)
    is_malicious = total_score >= settings.THREAT_SCORE_THRESHOLD

    sources = []
    if vt.get("detected"):
        sources.append("VirusTotal")
    if av.get("detected"):
        sources.append("AlienVault")
    if tf.get("detected"):
        sources.append("ThreatFox")

    return {
        "ip": ip,
        "threat_score": round(total_score, 2),
        "is_malicious": is_malicious,
        "virustotal_score": vt_score,
        "alienvault_score": av_score,
        "threatfox_score": tf_score,
        "sources": sources,
        "details": {
            "virustotal": vt.get("details", {}),
            "alienvault": av.get("details", {}),
            "threatfox": tf.get("details", {}),
        },
    }


async def fetch_nvd_cves(router_version: str = "7") -> list:
    """Fetch MikroTik-related CVEs from NVD."""
    if not settings.NVD_API_KEY:
        return []

    headers = {"apiKey": settings.NVD_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": "MikroTik RouterOS",
                    "resultsPerPage": 20,
                },
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            return []
    except Exception as e:
        logger.error(f"[NVD] Error fetching CVEs: {e}")
        return []
