from fastapi import APIRouter, Depends, HTTPException, Query
from models import User
from auth import get_current_user
from typing import Optional
import mikrotik

router = APIRouter(prefix="/mikrotik", tags=["MikroTik Monitor"])


@router.get("/interfaces")
async def get_interfaces(current_user: User = Depends(get_current_user)):
    """Get all network interfaces with RX/TX traffic statistics."""
    return await mikrotik.get_interfaces()


@router.get("/firewall/rules")
async def get_firewall_rules(
    chain: Optional[str] = Query(None, description="Filter by chain: input, forward, output"),
    current_user: User = Depends(get_current_user),
):
    """Get firewall filter rules. Optionally filter by chain."""
    return await mikrotik.get_firewall_rules(chain=chain)


@router.patch("/firewall/rules/{rule_id}/toggle")
async def toggle_firewall_rule(
    rule_id: str,
    disabled: bool = Query(..., description="True to disable, False to enable"),
    current_user: User = Depends(get_current_user),
):
    """Enable or disable a specific firewall rule."""
    result = await mikrotik.toggle_firewall_rule(rule_id, disabled)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to toggle rule"))
    return result


@router.get("/firewall/nat")
async def get_nat_rules(current_user: User = Depends(get_current_user)):
    """Get NAT rules (masquerade / dst-nat)."""
    return await mikrotik.get_nat_rules()


@router.get("/firewall/address-lists")
async def get_address_lists(current_user: User = Depends(get_current_user)):
    """Get all address list entries across all lists."""
    return await mikrotik.get_all_address_lists()


@router.get("/dhcp/leases")
async def get_dhcp_leases(current_user: User = Depends(get_current_user)):
    """Get DHCP server leases — all currently connected/known devices."""
    return await mikrotik.get_dhcp_leases()


@router.get("/connections")
async def get_active_connections(
    limit: int = Query(100, le=500),
    current_user: User = Depends(get_current_user),
):
    """Get active firewall connection tracking entries."""
    return await mikrotik.get_active_connections(limit=limit)


@router.get("/logs")
async def get_system_logs(
    count: int = Query(100, le=500),
    topics: Optional[str] = Query(None, description="Filter by topic e.g. firewall, system"),
    current_user: User = Depends(get_current_user),
):
    """Get MikroTik system log entries."""
    return await mikrotik.get_system_logs(count=count, topics=topics)


@router.get("/routes")
async def get_ip_routes(current_user: User = Depends(get_current_user)):
    """Get IP routing table."""
    return await mikrotik.get_ip_routes()


@router.get("/addresses")
async def get_ip_addresses(current_user: User = Depends(get_current_user)):
    """Get all configured IP addresses on interfaces."""
    return await mikrotik.get_ip_addresses()


@router.get("/identity")
async def get_identity(current_user: User = Depends(get_current_user)):
    """Get router hostname/identity."""
    return await mikrotik.get_system_identity()
