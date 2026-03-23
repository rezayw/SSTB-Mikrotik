from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, date
from database import get_db
from models import AttackLog, BlockedIP, ThreatIntelCache, User
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(AttackLog)
        .order_by(AttackLog.detected_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.post("/ingest")
async def ingest_syslog(
    event: SyslogEvent,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Endpoint for syslog container to push events."""
    # Log the attack attempt
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
        # Auto block immediately
        background_tasks.add_task(
            auto_block_ip,
            event.source_ip,
            cache.total_score,
            "local_cache",
            log.id,
            db,
        )
        return {"status": "queued_block", "cached_score": cache.total_score}

    # Queue deep analysis
    background_tasks.add_task(
        analyze_and_block,
        event.source_ip,
        log.id,
        db,
    )
    return {"status": "analyzing", "log_id": log.id}


async def analyze_and_block(ip: str, log_id: int, db: Session):
    """Background task: analyze IP and block if malicious."""
    try:
        result = await threat_intel.analyze_ip(ip)

        # Update cache
        cache = db.query(ThreatIntelCache).filter(
            ThreatIntelCache.ip_address == ip
        ).first()

        if cache:
            cache.virustotal_score = result["virustotal_score"]
            cache.alienvault_score = result["alienvault_score"]
            cache.threatfox_score = result["threatfox_score"]
            cache.total_score = result["threat_score"]
            cache.is_malicious = result["is_malicious"]
            cache.raw_data = json.dumps(result)
            cache.last_checked = datetime.utcnow()
        else:
            cache = ThreatIntelCache(
                ip_address=ip,
                virustotal_score=result["virustotal_score"],
                alienvault_score=result["alienvault_score"],
                threatfox_score=result["threatfox_score"],
                total_score=result["threat_score"],
                is_malicious=result["is_malicious"],
                raw_data=json.dumps(result),
            )
            db.add(cache)

        # Update log
        log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
        if log:
            log.threat_score = result["threat_score"]

        db.commit()

        # Auto block if malicious
        if result["is_malicious"] and settings.AUTO_BLOCK_ENABLED:
            await auto_block_ip(
                ip,
                result["threat_score"],
                ", ".join(result["sources"]),
                log_id,
                db,
            )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[analyze_and_block] Error for {ip}: {e}")


async def auto_block_ip(ip: str, score: float, source: str, log_id: int, db: Session):
    """Auto block an IP in both DB and MikroTik."""
    existing = db.query(BlockedIP).filter(
        BlockedIP.address == ip,
        BlockedIP.is_active == True,
    ).first()

    if existing:
        return

    blocked = BlockedIP(
        address=ip,
        threat_score=score,
        reason=f"Auto-blocked by SSTB (score: {score:.1f})",
        source=source,
        comment=f"Blocked by SSTB - {source} Match",
        is_active=True,
    )
    db.add(blocked)

    # Update log status
    log = db.query(AttackLog).filter(AttackLog.id == log_id).first()
    if log:
        log.status = "blocked"
        log.threat_score = score

    db.commit()

    # Push to MikroTik
    result = await mikrotik.block_ip(
        ip=ip,
        comment=f"Blocked by SSTB - {source} | Score: {score:.1f}",
        timeout="7d",
    )
    if result.get("success"):
        blocked.synced_to_mikrotik = True
        db.commit()


@router.get("/scan/{ip}", response_model=IPScanResult)
async def scan_ip(
    ip: str,
    current_user: User = Depends(get_current_user),
):
    """Manually trigger threat intelligence scan for an IP."""
    result = await threat_intel.analyze_ip(ip)
    return IPScanResult(**result)
