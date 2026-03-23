import httpx
import asyncio
import logging
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)

# AbuseIPDB attack category IDs → human-readable labels
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Brute-Force", 23: "IoT Targeted",
}


async def get_geolocation(ip: str) -> dict:
    """Get IP geolocation via ip-api.com (free, no key required)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,proxy,hosting"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "asn": data.get("as", ""),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "timezone": data.get("timezone", ""),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False),
                    }
            return {}
    except Exception as e:
        logger.error(f"[GeoIP] Error for {ip}: {e}")
        return {}


async def check_virustotal(ip: str) -> dict:
    """Check IP against VirusTotal — returns detailed engine breakdown."""
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
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values()) or 1
                score = ((malicious * 1.0 + suspicious * 0.5) / total) * 10

                # Extract top malicious engine names
                engines = attrs.get("last_analysis_results", {})
                flagged_engines = [
                    name for name, result in engines.items()
                    if result.get("category") in ("malicious", "suspicious")
                ][:10]

                return {
                    "score": round(min(score, 10.0), 2),
                    "detected": malicious > 0,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "flagged_engines": flagged_engines,
                    "reputation": attrs.get("reputation", 0),
                    "network": attrs.get("network", ""),
                    "as_owner": attrs.get("as_owner", ""),
                    "country": attrs.get("country", ""),
                    "details": stats,
                }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[VirusTotal] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_alienvault(ip: str) -> dict:
    """Check IP against AlienVault OTX — returns pulse details and malware families."""
    if not settings.ALIENVAULT_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Fetch general + malware sections in parallel
            general_resp, malware_resp = await asyncio.gather(
                client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers=headers,
                ),
                client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware",
                    headers=headers,
                ),
            )

            pulse_count = 0
            tags = []
            malware_families = []
            adversaries = []

            if general_resp.status_code == 200:
                data = general_resp.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                # Collect tags and adversaries from pulses
                for pulse in pulse_info.get("pulses", [])[:5]:
                    tags.extend(pulse.get("tags", []))
                    if pulse.get("adversary"):
                        adversaries.append(pulse["adversary"])

            if malware_resp.status_code == 200:
                mal_data = malware_resp.json()
                malware_families = list({
                    h.get("detections", {}).get("avast", "")
                    for h in mal_data.get("data", [])[:10]
                    if h.get("detections")
} - {""})[:5]

            score = min(pulse_count * 2.0, 10.0)
            return {
                "score": round(score, 2),
                "detected": pulse_count > 0,
                "pulse_count": pulse_count,
                "tags": list(set(tags))[:10],
                "malware_families": malware_families,
                "adversaries": list(set(adversaries))[:5],
                "details": {"pulses": pulse_count},
            }
    except Exception as e:
        logger.error(f"[AlienVault] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_threatfox(ip: str) -> dict:
    """Check IP against ThreatFox — returns IoC details and malware tags."""
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
                if data.get("query_status") == "ok":
                    iocs = data.get("data", [])
                    malware_names = list({i.get("malware_printable", "") for i in iocs} - {""})[:5]
                    threat_types = list({i.get("threat_type_desc", "") for i in iocs} - {""})[:5]
                    confidence_levels = [i.get("confidence_level", 0) for i in iocs]
                    avg_confidence = sum(confidence_levels) / len(confidence_levels) if confidence_levels else 0

                    score = min(len(iocs) * 3.0, 10.0)
                    return {
                        "score": round(score, 2),
                        "detected": len(iocs) > 0,
                        "ioc_count": len(iocs),
                        "malware_names": malware_names,
                        "threat_types": threat_types,
                        "avg_confidence": round(avg_confidence, 1),
                        "details": {"iocs_found": len(iocs)},
                    }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[ThreatFox] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def check_abuseipdb(ip: str) -> dict:
    """Check IP against AbuseIPDB — returns abuse confidence, reports, categories, ISP."""
    if not settings.ABUSEIPDB_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                confidence = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                distinct_users = data.get("numDistinctUsers", 0)
                categories = [
                    ABUSEIPDB_CATEGORIES.get(c, f"Category {c}")
                    for c in data.get("usageType_categories", [])
                    or (data.get("reports", [{}])[0].get("categories", []) if data.get("reports") else [])
                ][:5]

                score = min(confidence / 10.0, 10.0)
                return {
                    "score": round(score, 2),
                    "detected": confidence >= 25,
                    "confidence": confidence,
                    "total_reports": total_reports,
                    "distinct_users": distinct_users,
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "usage_type": data.get("usageType", ""),
                    "country_code": data.get("countryCode", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "categories": categories,
                    "last_reported": data.get("lastReportedAt", ""),
                    "details": {
                        "confidence": confidence,
                        "reports": total_reports,
                    },
                }
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[AbuseIPDB] Error checking {ip}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


def _classify_threat(vt: dict, av: dict, tf: dict, abuse: dict, geo: dict) -> dict:
    """Classify the type of threat based on source data."""
    categories = set()

    # From AbuseIPDB categories
    for cat in abuse.get("categories", []):
        if "SSH" in cat or "Brute" in cat or "FTP" in cat:
            categories.add("brute-force")
        elif "Port Scan" in cat:
            categories.add("port-scanner")
        elif "DDoS" in cat:
            categories.add("ddos")
        elif "Phishing" in cat or "Fraud" in cat:
            categories.add("phishing")
        elif "Spam" in cat:
            categories.add("spam")
        elif "Web App" in cat or "SQL" in cat:
            categories.add("web-attack")
        elif "Bot" in cat or "IoT" in cat:
            categories.add("botnet")

    # From ThreatFox threat types
    for tt in tf.get("threat_types", []):
        tt_lower = tt.lower()
        if "botnet" in tt_lower:
            categories.add("botnet")
        elif "malware" in tt_lower:
            categories.add("malware-c2")
        elif "phishing" in tt_lower:
            categories.add("phishing")

    # From AlienVault tags
    for tag in av.get("tags", []):
        tag_lower = tag.lower()
        if "scanner" in tag_lower or "scan" in tag_lower:
            categories.add("port-scanner")
        elif "brute" in tag_lower:
            categories.add("brute-force")
        elif "botnet" in tag_lower or "c2" in tag_lower:
            categories.add("botnet")
        elif "ransomware" in tag_lower:
            categories.add("ransomware")

    # Hosting/proxy indicators
    if geo.get("is_hosting"):
        categories.add("hosting-abuse")
    if geo.get("is_proxy"):
        categories.add("proxy/vpn")
    if abuse.get("is_tor"):
        categories.add("tor-exit-node")

    return {
        "categories": list(categories) if categories else ["unknown"],
        "primary": list(categories)[0] if categories else "unknown",
    }


async def analyze_ip(ip: str) -> dict:
    """Full threat intelligence analysis: VT + AV + ThreatFox + GeoIP."""
    vt, av, tf, geo = await asyncio.gather(
        check_virustotal(ip),
        check_alienvault(ip),
        check_threatfox(ip),
        get_geolocation(ip),
    )

    vt_score = vt.get("score", 0.0)
    av_score = av.get("score", 0.0)
    tf_score = tf.get("score", 0.0)

    # Weighted average: VT 40%, AV 45%, TF 15%
    # AlienVault diberi bobot lebih tinggi karena paling komprehensif datanya
    total_score = (vt_score * 0.40) + (av_score * 0.45) + (tf_score * 0.15)
    is_malicious = total_score >= settings.THREAT_SCORE_THRESHOLD

    # AbuseIPDB dihapus dari scoring — tidak mempengaruhi is_malicious
    abuse_score = 0.0
    abuse: dict = {}

    sources = []
    if vt.get("detected"):
        sources.append("VirusTotal")
    if av.get("detected"):
        sources.append("AlienVault")
    if tf.get("detected"):
        sources.append("ThreatFox")

    threat_classification = _classify_threat(vt, av, tf, abuse, geo)

    return {
        "ip": ip,
        "threat_score": round(total_score, 2),
        "is_malicious": is_malicious,
        # Per-source scores
        "virustotal_score": vt_score,
        "alienvault_score": av_score,
        "threatfox_score": tf_score,
        "abuseipdb_score": abuse_score,
        # Classification
        "threat_categories": threat_classification["categories"],
        "threat_primary": threat_classification["primary"],
        "sources": sources,
        # Geolocation
        "geo": geo,
        "country": geo.get("country", ""),
        "country_code": geo.get("country_code", ""),
        "city": geo.get("city", ""),
        "isp": geo.get("isp", "") or vt.get("as_owner", "") or abuse.get("isp", ""),
        "asn": geo.get("asn", ""),
        "is_tor": abuse.get("is_tor", False),
        "is_proxy": geo.get("is_proxy", False) or geo.get("is_hosting", False),
        # Per-source details
        "virustotal": {
            "score": vt_score,
            "detected": vt.get("detected", False),
            "malicious_engines": vt.get("malicious", 0),
            "suspicious_engines": vt.get("suspicious", 0),
            "total_engines": vt.get("total_engines", 0),
            "flagged_engines": vt.get("flagged_engines", []),
            "reputation": vt.get("reputation", 0),
            "network": vt.get("network", ""),
        },
        "alienvault": {
            "score": av_score,
            "detected": av.get("detected", False),
            "pulse_count": av.get("pulse_count", 0),
            "tags": av.get("tags", []),
            "malware_families": av.get("malware_families", []),
            "adversaries": av.get("adversaries", []),
        },
        "threatfox": {
            "score": tf_score,
            "detected": tf.get("detected", False),
            "ioc_count": tf.get("ioc_count", 0),
            "malware_names": tf.get("malware_names", []),
            "threat_types": tf.get("threat_types", []),
            "avg_confidence": tf.get("avg_confidence", 0),
        },
        "abuseipdb": {
            "score": abuse_score,
            "detected": abuse.get("detected", False),
            "confidence": abuse.get("confidence", 0),
            "total_reports": abuse.get("total_reports", 0),
            "distinct_users": abuse.get("distinct_users", 0),
            "isp": abuse.get("isp", ""),
            "domain": abuse.get("domain", ""),
            "usage_type": abuse.get("usage_type", ""),
            "is_tor": abuse.get("is_tor", False),
            "categories": abuse.get("categories", []),
            "last_reported": abuse.get("last_reported", ""),
        },
        # Legacy flat structure
        "details": {
            "virustotal": vt.get("details", {}),
            "alienvault": av.get("details", {}),
            "threatfox": tf.get("details", {}),
            "abuseipdb": abuse.get("details", {}),
        },
    }


async def check_urlscan(url: str) -> dict:
    """Submit URL to URLScan for analysis."""
    if not settings.URLSCAN_API_KEY:
        return {"score": 0.0, "detected": False, "details": {}}

    headers = {"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"}
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
                return {"score": 5.0, "detected": True, "scan_id": data.get("uuid"), "details": data}
            return {"score": 0.0, "detected": False, "details": {}}
    except Exception as e:
        logger.error(f"[URLScan] Error scanning {url}: {e}")
        return {"score": 0.0, "detected": False, "details": {}}


async def fetch_nvd_cves(router_version: str = "7") -> list:
    """Fetch MikroTik-related CVEs from NVD."""
    if not settings.NVD_API_KEY:
        return []
    headers = {"apiKey": settings.NVD_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": "MikroTik RouterOS", "resultsPerPage": 20},
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            return []
    except Exception as e:
        logger.error(f"[NVD] Error fetching CVEs: {e}")
        return []


async def fetch_cisa_kev() -> list:
    """Fetch CISA Known Exploited Vulnerabilities catalog (no API key required)."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                # Filter for network/router related
                keywords = ["mikrotik", "routeros", "router", "firewall", "vpn", "network"]
                relevant = [
                    v for v in vulns
                    if any(kw in v.get("product", "").lower() or kw in v.get("vendorProject", "").lower()
                           for kw in keywords)
                ]
                return relevant
            return []
    except Exception as e:
        logger.error(f"[CISA KEV] Error fetching: {e}")
        return []
