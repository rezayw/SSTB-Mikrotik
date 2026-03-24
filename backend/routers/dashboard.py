from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from datetime import datetime, timedelta
from database import get_db
from models import BlockedIP, AttackLog, CVEAlert, User, Whitelist
from schemas import DashboardStats, CVEAlertOut
from auth import get_current_user
from typing import List
import mikrotik

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    total_blocked = db.query(BlockedIP).filter(BlockedIP.is_active == True).count()
    blocked_today = db.query(BlockedIP).filter(
        BlockedIP.is_active == True,
        BlockedIP.blocked_at >= today,
    ).count()

    threats_detected = db.query(AttackLog).count()
    threats_today = db.query(AttackLog).filter(AttackLog.detected_at >= today).count()

    active_cve_alerts = db.query(CVEAlert).count()
    critical_cve_count = db.query(CVEAlert).filter(CVEAlert.severity == "CRITICAL").count()

    mikrotik_connected = await mikrotik.check_connection()

    return DashboardStats(
        total_blocked=total_blocked,
        blocked_today=blocked_today,
        threats_detected=threats_detected,
        threats_today=threats_today,
        active_cve_alerts=active_cve_alerts,
        critical_cve_count=critical_cve_count,
        mikrotik_connected=mikrotik_connected,
        auto_block_enabled=True,
        last_sync=datetime.utcnow(),
    )


@router.get("/cve-alerts", response_model=List[CVEAlertOut])
def get_cve_alerts(
    limit: int = 10,
    severity: str = None,
    kev_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(CVEAlert)
    if severity:
        q = q.filter(CVEAlert.severity == severity.upper())
    if kev_only:
        q = q.filter(CVEAlert.is_kev == True)
    return q.order_by(CVEAlert.cvss_score.desc()).limit(limit).all()


@router.get("/mikrotik-status")
async def get_mikrotik_status(current_user: User = Depends(get_current_user)):
    """Get MikroTik router status, system info, and uptime."""
    return await mikrotik.get_router_info()


@router.get("/attack-timeline")
def get_attack_timeline(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get attack counts per day for the last N days."""
    result = []
    for i in range(days - 1, -1, -1):
        day_start = datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)

        count = db.query(AttackLog).filter(
            AttackLog.detected_at >= day_start,
            AttackLog.detected_at < day_end,
        ).count()

        blocked = db.query(AttackLog).filter(
            AttackLog.detected_at >= day_start,
            AttackLog.detected_at < day_end,
            AttackLog.status == "blocked",
        ).count()

        result.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "attacks": count,
            "blocked": blocked,
        })
    return result


@router.get("/top-attackers")
def get_top_attackers(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get top attacking IPs by frequency."""
    results = (
        db.query(
            AttackLog.source_ip,
            AttackLog.country,
            AttackLog.country_code,
            AttackLog.isp,
            func.count(AttackLog.id).label("count"),
            func.max(AttackLog.threat_score).label("max_score"),
        )
        .group_by(AttackLog.source_ip, AttackLog.country, AttackLog.country_code, AttackLog.isp)
        .order_by(func.count(AttackLog.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "ip": r.source_ip,
            "count": r.count,
            "max_score": r.max_score,
            "country": r.country,
            "country_code": r.country_code,
            "isp": r.isp,
        }
        for r in results
    ]


@router.get("/geo-stats")
def get_geo_stats(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get attack counts grouped by country — for geographic analytics."""
    results = (
        db.query(
            AttackLog.country,
            AttackLog.country_code,
            func.count(AttackLog.id).label("attack_count"),
            func.count(
                func.distinct(AttackLog.source_ip)
            ).label("unique_ips"),
            func.avg(AttackLog.threat_score).label("avg_score"),
        )
        .filter(AttackLog.country != None, AttackLog.country != "")
        .group_by(AttackLog.country, AttackLog.country_code)
        .order_by(func.count(AttackLog.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "country": r.country,
            "country_code": r.country_code or "XX",
            "attack_count": r.attack_count,
            "unique_ips": r.unique_ips,
            "avg_score": round(r.avg_score or 0, 2),
        }
        for r in results
    ]


@router.get("/protocol-stats")
def get_protocol_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get attack breakdown by attack type and protocol."""
    attack_types = (
        db.query(
            AttackLog.attack_type,
            func.count(AttackLog.id).label("count"),
        )
        .filter(AttackLog.attack_type != None)
        .group_by(AttackLog.attack_type)
        .order_by(func.count(AttackLog.id).desc())
        .limit(10)
        .all()
    )

    protocols = (
        db.query(
            AttackLog.protocol,
            func.count(AttackLog.id).label("count"),
        )
        .filter(AttackLog.protocol != None)
        .group_by(AttackLog.protocol)
        .order_by(func.count(AttackLog.id).desc())
        .all()
    )

    target_ports = (
        db.query(
            AttackLog.target_port,
            func.count(AttackLog.id).label("count"),
        )
        .filter(AttackLog.target_port != None)
        .group_by(AttackLog.target_port)
        .order_by(func.count(AttackLog.id).desc())
        .limit(10)
        .all()
    )

    return {
        "attack_types": [{"type": r.attack_type, "count": r.count} for r in attack_types],
        "protocols": [{"protocol": r.protocol, "count": r.count} for r in protocols],
        "target_ports": [{"port": r.target_port, "count": r.count} for r in target_ports],
    }


@router.get("/hourly-heatmap")
def get_hourly_heatmap(
    days: int = 30,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get attack distribution by hour of day (0–23) for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)

    logs = (
        db.query(AttackLog.detected_at)
        .filter(AttackLog.detected_at >= since)
        .all()
    )

    hour_counts = [0] * 24
    for log in logs:
        if log.detected_at:
            hour_counts[log.detected_at.hour] += 1

    return [{"hour": h, "count": hour_counts[h]} for h in range(24)]


@router.get("/threat-score-distribution")
def get_threat_score_distribution(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get distribution of threat scores across attack logs (bucketed 0-10)."""
    buckets = {"0-2": 0, "2-4": 0, "4-6": 0, "6-8": 0, "8-10": 0}

    logs = db.query(AttackLog.threat_score).filter(AttackLog.threat_score != None).all()
    for log in logs:
        s = log.threat_score
        if s < 2:
            buckets["0-2"] += 1
        elif s < 4:
            buckets["2-4"] += 1
        elif s < 6:
            buckets["4-6"] += 1
        elif s < 8:
            buckets["6-8"] += 1
        else:
            buckets["8-10"] += 1

    return [{"range": k, "count": v} for k, v in buckets.items()]


@router.get("/summary-counts")
def get_summary_counts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Extended summary: blocked IPs, whitelist, CVE KEV, unique attackers."""
    total_blocked = db.query(BlockedIP).filter(BlockedIP.is_active == True).count()
    total_whitelist = db.query(Whitelist).count()
    total_cve = db.query(CVEAlert).count()
    kev_count = db.query(CVEAlert).filter(CVEAlert.is_kev == True).count()
    unique_attackers = db.query(func.distinct(AttackLog.source_ip)).count()
    tor_count = db.query(BlockedIP).filter(
        BlockedIP.is_tor == True, BlockedIP.is_active == True
    ).count()

    return {
        "total_blocked": total_blocked,
        "total_whitelist": total_whitelist,
        "total_cve": total_cve,
        "kev_count": kev_count,
        "unique_attackers": unique_attackers,
        "tor_exits_blocked": tor_count,
    }


# ── CVE Ingest (called by worker) ─────────────────────────────────────────────

from pydantic import BaseModel
from typing import Optional as Opt

class CVEIngest(BaseModel):
    cve_id: str
    description: Opt[str] = None
    severity: Opt[str] = "CRITICAL"
    cvss_score: float = 0.0
    published_date: Opt[str] = None
    affected_product: Opt[str] = None
    is_kev: bool = False
    epss_score: float = 0.0


@router.post("/cve-alerts/ingest")
def ingest_cve(entry: CVEIngest, db: Session = Depends(get_db)):
    """Upsert a CVE alert from worker (no auth — internal use only)."""
    if not entry.cve_id:
        return {"status": "skipped", "reason": "empty cve_id"}

    pub = None
    if entry.published_date:
        try:
            from datetime import datetime as dt
            pub = dt.fromisoformat(entry.published_date.replace("Z", "+00:00").replace("+00:00", ""))
        except Exception:
            pass

    existing = db.query(CVEAlert).filter(CVEAlert.cve_id == entry.cve_id).first()
    if existing:
        existing.description = entry.description or existing.description
        existing.severity = (entry.severity or "CRITICAL").upper()
        existing.cvss_score = entry.cvss_score
        existing.is_kev = entry.is_kev
        existing.affected_product = entry.affected_product or existing.affected_product
        existing.epss_score = entry.epss_score
        existing.last_modified = datetime.utcnow()
        if pub:
            existing.published_date = pub
    else:
        db.add(CVEAlert(
            cve_id=entry.cve_id,
            description=entry.description,
            severity=(entry.severity or "CRITICAL").upper(),
            cvss_score=entry.cvss_score,
            is_kev=entry.is_kev,
            affected_product=entry.affected_product,
            epss_score=entry.epss_score,
            published_date=pub,
            last_modified=datetime.utcnow(),
        ))
    db.commit()
    return {"status": "ok", "cve_id": entry.cve_id}


@router.post("/cleanup-expired")
async def cleanup_expired_blocks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Deactivate and unblock expired blocked IPs."""
    now = datetime.utcnow()
    expired = db.query(BlockedIP).filter(
        BlockedIP.is_active == True,
        BlockedIP.expires_at != None,
        BlockedIP.expires_at <= now,
    ).all()

    cleaned = 0
    failed = 0
    for ip in expired:
        try:
            await mikrotik.unblock_ip(ip.address)
        except Exception:
            failed += 1
        ip.is_active = False
        cleaned += 1

    db.commit()
    return {"cleaned": cleaned, "failed_mikrotik": failed, "message": f"Deactivated {cleaned} expired IPs"}
