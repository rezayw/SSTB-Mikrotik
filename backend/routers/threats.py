from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime
from database import get_db
from models import AttackLog, BlockedIP, ThreatIntelCache, Whitelist, User
from schemas import AttackLogOut, SyslogEvent, IPScanResult
from auth import get_current_user
import threat_intel
import mikrotik
import json
from config import settings

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get("/logs", response_model=List[AttackLogOut])
def get_attack_logs(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = Query(None, description="Filter by status: pending, blocked, analyzing"),
    attack_type: Optional[str] = Query(None),
    country_code: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(AttackLog)
    if status:
        q = q.filter(AttackLog.status == status)
    if attack_type:
        q = q.filter(AttackLog.attack_type == attack_type)
    if country_code:
        q = q.filter(AttackLog.country_code == country_code)
    if min_score is not None:
        q = q.filter(AttackLog.threat_score >= min_score)
    return q.order_by(AttackLog.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/scan/{ip}")
async def scan_ip(
    ip: str,
    use_cache: bool = Query(True, description="Return cached result if available (< 1 hour old)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger full threat intelligence scan for an IP address."""
    if use_cache:
        from datetime import timedelta
        cache = db.query(ThreatIntelCache).filter(
            ThreatIntelCache.ip_address == ip
        ).first()
        if cache and cache.last_checked > datetime.utcnow() - timedelta(hours=1):
            if cache.raw_data:
                cached = json.loads(cache.raw_data)
                cached["cached"] = True
                cached["cache_age_minutes"] = int(
                    (datetime.utcnow() - cache.last_checked).total_seconds() / 60
                )
                return cached

    result = await threat_intel.analyze_ip(ip)

    # Update cache
    _update_cache(db, ip, result)

    result["cached"] = False
    return result


@router.get("/cache/{ip}")
def get_cached_result(
    ip: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get cached threat intelligence result for an IP."""
    cache = db.query(ThreatIntelCache).filter(ThreatIntelCache.ip_address == ip).first()
    if not cache:
        raise HTTPException(status_code=404, detail="No cached result for this IP")
    if cache.raw_data:
        return json.loads(cache.raw_data)
    return {
        "ip": ip,
        "total_score": cache.total_score,
        "is_malicious": cache.is_malicious,
        "last_checked": cache.last_checked,
    }


@router.post("/ingest")
async def ingest_syslog(
    event: SyslogEvent,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Endpoint for syslog container to push attack events."""
    # Check if whitelisted
    if db.query(Whitelist).filter(Whitelist.address == event.source_ip).first():
        return {"status": "whitelisted", "ip": event.source_ip}

    log = AttackLog(
        source_ip=event.source_ip,
        target_port=event.target_port,
        protocol=event.protocol,
        attack_type=event.attack_type,
        raw_log=event.raw_log,
        status="pending",
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    # Quick check: already blocked?
    if db.query(BlockedIP).filter(
        BlockedIP.address == event.source_ip,
        BlockedIP.is_active == True,
    ).first():
        log.status = "blocked"
        db.commit()
        return {"status": "already_blocked"}

    # Check local cache
    cache = db.query(ThreatIntelCache).filter(
        ThreatIntelCache.ip_address == event.source_ip
    ).first()

    if cache and cache.is_malicious:
        background_tasks.add_task(
            auto_block_ip,
            event.source_ip,
            cache.total_score,
            "local_cache",
            log.id,
            db,
        )
        return {"status": "queued_block", "cached_score": cache.total_score}

    log.status = "analyzing"
    db.commit()
    background_tasks.add_task(analyze_and_block, event.source_ip, log.id, db)
    return {"status": "analyzing", "log_id": log.id}


@router.get("/stats/summary")
def get_threat_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Summary stats for the threats section."""
    total = db.query(AttackLog).count()
    by_status = (
        db.query(AttackLog.status, func.count(AttackLog.id))
        .group_by(AttackLog.status)
        .all()
    )
    by_type = (
        db.query(AttackLog.attack_type, func.count(AttackLog.id))
        .filter(AttackLog.attack_type != None)
        .group_by(AttackLog.attack_type)
        .order_by(func.count(AttackLog.id).desc())
        .limit(5)
        .all()
    )
    avg_score = db.query(func.avg(AttackLog.threat_score)).scalar() or 0.0
    cache_count = db.query(ThreatIntelCache).count()

    return {
        "total_logs": total,
        "by_status": {s: c for s, c in by_status},
        "top_attack_types": [{"type": t, "count": c} for t, c in by_type],
        "avg_threat_score": round(avg_score, 2),
        "cached_ips": cache_count,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _update_cache(db: Session, ip: str, result: dict):
    """Upsert ThreatIntelCache with full analysis result."""
    cache = db.query(ThreatIntelCache).filter(ThreatIntelCache.ip_address == ip).first()
    geo = result.get("geo", {})
    categories = result.get("threat_categories", [])

    if cache:
        cache.virustotal_score = result.get("virustotal_score", 0.0)
        cache.alienvault_score = result.get("alienvault_score", 0.0)
        cache.threatfox_score = result.get("threatfox_score", 0.0)
        cache.abuseipdb_score = result.get("abuseipdb_score", 0.0)
        cache.total_score = result.get("threat_score", 0.0)
        cache.is_malicious = result.get("is_malicious", False)
        cache.country = geo.get("country", "")
        cache.country_code = geo.get("country_code", "")
        cache.isp = geo.get("isp", "")
        cache.threat_categories = ",".join(categories)
        cache.raw_data = json.dumps(result, default=str)
        cache.last_checked = datetime.utcnow()
    else:
        cache = ThreatIntelCache(
            ip_address=ip,
            virustotal_score=result.get("virustotal_score", 0.0),
            alienvault_score=result.get("alienvault_score", 0.0),
            threatfox_score=result.get("threatfox_score", 0.0),
            abuseipdb_score=result.get("abuseipdb_score", 0.0),
            total_score=result.get("threat_score", 0.0),
            is_malicious=result.get("is_malicious", False),
            country=geo.get("country", ""),
            country_code=geo.get("country_code", ""),
            isp=geo.get("isp", ""),
            threat_categories=",".join(categories),
            raw_data=json.dumps(result, default=str),
        )
        db.add(cache)
    db.commit()


async def analyze_and_block(ip: str, log_id: int, db: Session):
    """Background task: full analysis and auto-block if malicious."""
    try:
        result = await threat_intel.analyze_ip(ip)
        _update_cache(db, ip, result)

        geo = result.get("geo", {})
        categories = result.get("threat_categories", [])

        log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
        if log:
            log.threat_score = result["threat_score"]
            log.country = geo.get("country", "")
            log.country_code = geo.get("country_code", "")
            log.city = geo.get("city", "")
            log.isp = geo.get("isp", "")
            log.asn = geo.get("asn", "")
            log.threat_categories = ",".join(categories)
            log.status = "analyzing"
        db.commit()

        if result["is_malicious"] and settings.AUTO_BLOCK_ENABLED:
            await auto_block_ip(
                ip,
                result["threat_score"],
                ", ".join(result.get("sources", [])),
                log_id,
                db,
                geo=geo,
                categories=categories,
                is_tor=result.get("is_tor", False),
                is_proxy=result.get("is_proxy", False),
            )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[analyze_and_block] Error for {ip}: {e}")


async def auto_block_ip(
    ip: str,
    score: float,
    source: str,
    log_id: int,
    db: Session,
    geo: dict = None,
    categories: list = None,
    is_tor: bool = False,
    is_proxy: bool = False,
):
    """Auto block an IP in DB and push to MikroTik firewall."""
    existing = db.query(BlockedIP).filter(
        BlockedIP.address == ip, BlockedIP.is_active == True
    ).first()
    if existing:
        return

    geo = geo or {}
    categories = categories or []

    blocked = BlockedIP(
        address=ip,
        threat_score=score,
        reason=f"Auto-blocked by SSTB (score: {score:.1f})",
        source=source,
        comment=f"Blocked by SSTB — {source} | Score: {score:.1f}",
        country=geo.get("country", ""),
        country_code=geo.get("country_code", ""),
        city=geo.get("city", ""),
        isp=geo.get("isp", ""),
        asn=geo.get("asn", ""),
        threat_categories=",".join(categories),
        is_tor=is_tor,
        is_proxy=is_proxy,
        is_active=True,
    )
    db.add(blocked)

    log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
    if log:
        log.status = "blocked"
        log.threat_score = score

    db.commit()

    result = await mikrotik.block_ip(
        ip=ip,
        comment=f"SSTB | {source} | Score:{score:.1f} | {','.join(categories[:2]) or 'threat'}",
        timeout="7d",
    )
    if result.get("success"):
        blocked.synced_to_mikrotik = True
        db.commit()
