from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Whitelist, User
from schemas import WhitelistCreate, WhitelistOut
from auth import get_current_user
from typing import List
import mikrotik

router = APIRouter(prefix="/whitelist", tags=["Whitelist"])


@router.get("/", response_model=List[WhitelistOut])
def get_whitelist(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all whitelisted IP addresses."""
    return (
        db.query(Whitelist)
        .order_by(Whitelist.added_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.post("/", response_model=WhitelistOut)
async def add_to_whitelist(
    entry: WhitelistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add an IP address to the whitelist."""
    existing = db.query(Whitelist).filter(Whitelist.address == entry.address).first()
    if existing:
        raise HTTPException(status_code=409, detail="IP already in whitelist")

    wl = Whitelist(
        address=entry.address,
        reason=entry.reason,
        comment=entry.comment,
        added_by=current_user.username,
        synced_to_mikrotik=False,
    )
    db.add(wl)
    db.commit()
    db.refresh(wl)

    # Sync to MikroTik
    result = await mikrotik.whitelist_ip(
        entry.address,
        comment=f"SSTB Whitelist: {entry.reason or entry.comment or ''}",
    )
    if result.get("success"):
        wl.synced_to_mikrotik = True
        db.commit()

    return wl


@router.delete("/{ip_address}")
async def remove_from_whitelist(
    ip_address: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove an IP address from the whitelist."""
    entry = db.query(Whitelist).filter(Whitelist.address == ip_address).first()
    if not entry:
        raise HTTPException(status_code=404, detail="IP not in whitelist")

    await mikrotik.remove_whitelist_ip(ip_address)
    db.delete(entry)
    db.commit()
    return {"message": f"{ip_address} removed from whitelist"}


@router.post("/sync")
async def sync_whitelist_to_mikrotik(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Push all unsynced whitelist entries to MikroTik, then pull any missing entries back."""
    pushed = 0
    failed = 0

    # 1. Push unsynced DB entries → MikroTik
    unsynced = db.query(Whitelist).filter(Whitelist.synced_to_mikrotik == False).all()
    for wl in unsynced:
        result = await mikrotik.whitelist_ip(
            wl.address,
            comment=f"SSTB Whitelist: {wl.reason or wl.comment or ''}",
        )
        if result.get("success"):
            wl.synced_to_mikrotik = True
            pushed += 1
        else:
            failed += 1
    db.commit()

    # 2. Pull entries from MikroTik that are not yet in DB
    pulled = 0
    from mikrotik import get_mikrotik_client, MIKROTIK_WHITELIST
    try:
        async with await get_mikrotik_client() as client:
            response = await client.get(
                "/rest/ip/firewall/address-list",
                params={"list": MIKROTIK_WHITELIST},
            )
            if response.status_code == 200:
                for entry in response.json():
                    ip = entry.get("address", "")
                    if ip and not db.query(Whitelist).filter(Whitelist.address == ip).first():
                        db.add(Whitelist(
                            address=ip,
                            reason="Imported from MikroTik",
                            comment=entry.get("comment", ""),
                            added_by="mikrotik-sync",
                            synced_to_mikrotik=True,
                        ))
                        pulled += 1
                db.commit()
    except Exception:
        pass

    return {
        "pushed_to_mikrotik": pushed,
        "pulled_from_mikrotik": pulled,
        "failed": failed,
        "message": f"Pushed {pushed}, pulled {pulled}, failed {failed}",
    }
