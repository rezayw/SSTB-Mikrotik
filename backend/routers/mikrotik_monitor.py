from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from models import User, MikroTikDevice
from auth import get_current_user
from database import get_db
from typing import Optional
import mikrotik

router = APIRouter(prefix="/mikrotik", tags=["MikroTik Monitor"])


def _resolve_device(device_id: Optional[int], db: Session) -> Optional[dict]:
    """Return device config dict for a given device_id, or None for the default."""
    if device_id is None:
        return None
    device = db.query(MikroTikDevice).filter(
        MikroTikDevice.id == device_id,
        MikroTikDevice.is_active == True,
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return {
        "host": device.host,
        "port": device.port,
        "use_ssl": device.use_ssl,
        "api_user": device.api_user,
        "api_password": device.api_password,
    }


@router.get("/interfaces")
async def get_interfaces(
    device_id: Optional[int] = Query(None, description="Device ID — omit for default"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all network interfaces with RX/TX traffic statistics."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_interfaces(device=device)


@router.get("/firewall/rules")
async def get_firewall_rules(
    chain: Optional[str] = Query(None, description="Filter by chain: input, forward, output"),
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get firewall filter rules. Optionally filter by chain."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_firewall_rules(chain=chain, device=device)


@router.patch("/firewall/rules/{rule_id}/toggle")
async def toggle_firewall_rule(
    rule_id: str,
    disabled: bool = Query(..., description="True to disable, False to enable"),
    current_user: User = Depends(get_current_user),
):
    """Enable or disable a specific firewall rule (on default device)."""
    result = await mikrotik.toggle_firewall_rule(rule_id, disabled)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to toggle rule"))
    return result


@router.get("/firewall/nat")
async def get_nat_rules(
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get NAT rules (masquerade / dst-nat)."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_nat_rules(device=device)


@router.get("/firewall/address-lists")
async def get_address_lists(
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all address list entries across all lists."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_all_address_lists(device=device)


@router.get("/dhcp/leases")
async def get_dhcp_leases(
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get DHCP server leases — all currently connected/known devices."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_dhcp_leases(device=device)


@router.get("/connections")
async def get_active_connections(
    limit: int = Query(100, le=500),
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get active firewall connection tracking entries."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_active_connections(limit=limit, device=device)


@router.get("/logs")
async def get_system_logs(
    count: int = Query(100, le=500),
    topics: Optional[str] = Query(None, description="Filter by topic e.g. firewall, system"),
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MikroTik system log entries."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_system_logs(count=count, topics=topics, device=device)


@router.get("/routes")
async def get_ip_routes(
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get IP routing table."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_ip_routes(device=device)


@router.get("/addresses")
async def get_ip_addresses(
    device_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all configured IP addresses on interfaces."""
    device = _resolve_device(device_id, db)
    return await mikrotik.get_ip_addresses(device=device)


@router.get("/identity")
async def get_identity(current_user: User = Depends(get_current_user)):
    """Get router hostname/identity."""
    return await mikrotik.get_system_identity()
