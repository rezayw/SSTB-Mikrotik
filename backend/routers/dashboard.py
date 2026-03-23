from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, date, timedelta
from database import get_db
from models import BlockedIP, AttackLog, CVEAlert, User
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
    threats_today = db.query(AttackLog).filter(
        AttackLog.detected_at >= today
    ).count()

    active_cve_alerts = db.query(CVEAlert).count()
    critical_cve_count = db.query(CVEAlert).filter(
        CVEAlert.severity == "CRITICAL"
    ).count()

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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(CVEAlert)
        .order_by(CVEAlert.cvss_score.desc())
        .limit(limit)
        .all()
    )


@router.get("/mikrotik-status")
async def get_mikrotik_status(
    current_user: User = Depends(get_current_user),
):
    """Get MikroTik router status and info."""
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
            func.count(AttackLog.id).label("count"),
            func.max(AttackLog.threat_score).label("max_score"),
        )
        .group_by(AttackLog.source_ip)
        .order_by(func.count(AttackLog.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {"ip": r.source_ip, "count": r.count, "max_score": r.max_score}
        for r in results
    ]
