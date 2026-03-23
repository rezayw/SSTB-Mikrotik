from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from database import get_db
from models import BlockedIP, AttackLog, User
from schemas import BlockedIPCreate, BlockedIPOut
from auth import get_current_user
import mikrotik

router = APIRouter(prefix="/blocklist", tags=["Blocklist"])


@router.get("/", response_model=List[BlockedIPOut])
def get_blocklist(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(BlockedIP)
    if active_only:
        query = query.filter(BlockedIP.is_active == True)
    return query.order_by(BlockedIP.blocked_at.desc()).offset(skip).limit(limit).all()


@router.post("/", response_model=BlockedIPOut, status_code=201)
async def block_ip(
    data: BlockedIPCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Check if already blocked
    existing = db.query(BlockedIP).filter(BlockedIP.address == data.address).first()
    if existing and existing.is_active:
        raise HTTPException(status_code=400, detail="IP is already blocked")

    expires_at = None
    if data.expires_hours:
        expires_at = datetime.utcnow() + timedelta(hours=data.expires_hours)

    # Try to enrich with geo + threat intel
    geo: dict = {}
    threat_score: float = 0.0
    country = ""
    country_code = ""
    city = ""
    isp = ""
    asn = ""
    threat_categories = ""
    is_tor = False
    is_proxy = False
    try:
        import threat_intel as ti
        result = await ti.analyze_ip(data.address)
        geo = result.get("geo", {})
        threat_score = result.get("threat_score", 0.0) or 0.0
        country = geo.get("country", "")
        country_code = geo.get("country_code", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")
        asn = geo.get("asn", "")
        threat_categories = ",".join(result.get("threat_categories", []))
        is_tor = result.get("is_tor", False)
        is_proxy = result.get("is_proxy", False)
        # Update cache
        from routers.threats import _update_cache
        _update_cache(db, data.address, result)
    except Exception:
        pass

    if existing:
        # Reactivate existing (previously unblocked) entry
        existing.reason = data.reason
        existing.source = data.source
        existing.comment = data.comment
        existing.expires_at = expires_at
        existing.threat_score = threat_score
        existing.country = country
        existing.country_code = country_code
        existing.city = city
        existing.isp = isp
        existing.asn = asn
        existing.threat_categories = threat_categories
        existing.is_tor = is_tor
        existing.is_proxy = is_proxy
        existing.is_active = True
        existing.synced_to_mikrotik = False
        existing.blocked_at = datetime.utcnow()
        blocked = existing
    else:
        blocked = BlockedIP(
            address=data.address,
            reason=data.reason,
            source=data.source,
            comment=data.comment,
            expires_at=expires_at,
            threat_score=threat_score,
            country=country,
            country_code=country_code,
            city=city,
            isp=isp,
            asn=asn,
            threat_categories=threat_categories,
            is_tor=is_tor,
            is_proxy=is_proxy,
            is_active=True,
            synced_to_mikrotik=False,
        )
        db.add(blocked)

    # Also update attack log status
    db.query(AttackLog).filter(
        AttackLog.source_ip == data.address,
        AttackLog.status == "pending",
    ).update({"status": "blocked"})

    db.commit()
    db.refresh(blocked)

    # Push to MikroTik
    timeout_str = f"{data.expires_hours}h" if data.expires_hours else "7d"
    result = await mikrotik.block_ip(
        ip=data.address,
        comment=data.comment or f"Blocked by SSTB - {data.source}",
        timeout=timeout_str,
    )
    if result.get("success"):
        blocked.synced_to_mikrotik = True
        db.commit()

    return blocked


@router.delete("/{ip_address}")
async def unblock_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    blocked = db.query(BlockedIP).filter(
        BlockedIP.address == ip_address,
        BlockedIP.is_active == True,
    ).first()

    if not blocked:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")

    # Remove from MikroTik
    await mikrotik.unblock_ip(ip_address)

    blocked.is_active = False
    db.commit()

    return {"message": f"IP {ip_address} has been unblocked"}


@router.post("/sync")
async def sync_from_mikrotik(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Sync blocklist from MikroTik."""
    entries = await mikrotik.get_blocklist()
    synced = 0

    for entry in entries:
        ip = entry.get("address")
        if not ip:
            continue

        existing = db.query(BlockedIP).filter(BlockedIP.address == ip).first()
        if not existing:
            blocked = BlockedIP(
                address=ip,
                reason="Synced from MikroTik",
                source="mikrotik",
                comment=entry.get("comment", ""),
                is_active=True,
                synced_to_mikrotik=True,
            )
            db.add(blocked)
            synced += 1

    db.commit()
    return {"message": f"Synced {synced} new IPs from MikroTik", "total": len(entries)}
