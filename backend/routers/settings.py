from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import asyncio

from database import get_db
from models import MikroTikDevice, User
from schemas import (
    MikroTikDeviceCreate, MikroTikDeviceUpdate,
    MikroTikDeviceOut, TopologyNode, TopologyResponse,
)
from auth import get_current_user
import mikrotik as mt

router = APIRouter(prefix="/settings", tags=["Settings"])


def _device_to_config(device: MikroTikDevice) -> dict:
    return {
        "host": device.host,
        "port": device.port,
        "use_ssl": device.use_ssl,
        "api_user": device.api_user,
        "api_password": device.api_password,
    }


def _apply_status(db: Session, device: MikroTikDevice, status: dict):
    """Write connection check result into a device record."""
    device.last_checked = datetime.utcnow()
    if status.get("connected"):
        device.last_status = "online"
        device.router_identity = status.get("identity", "")
        device.router_model = status.get("model", "")
        device.router_version = status.get("version", "")
        device.router_board = status.get("board", "")
        device.uptime = status.get("uptime", "")
        device.cpu_load = status.get("cpu_load")
        device.free_memory = status.get("free_memory")
        device.total_memory = status.get("total_memory")
        device.interface_count = status.get("interface_count")
    else:
        device.last_status = "offline"
    db.commit()
    db.refresh(device)


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("/mikrotik", response_model=List[MikroTikDeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all configured MikroTik devices."""
    return db.query(MikroTikDevice).order_by(
        MikroTikDevice.is_default.desc(), MikroTikDevice.created_at
    ).all()


@router.post("/mikrotik", response_model=MikroTikDeviceOut)
async def add_device(
    payload: MikroTikDeviceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a new MikroTik device. Automatically tests connection on creation."""
    # If setting as default, unset others
    if payload.is_default:
        db.query(MikroTikDevice).update({"is_default": False})

    device = MikroTikDevice(
        name=payload.name,
        host=payload.host,
        port=payload.port,
        use_ssl=payload.use_ssl,
        api_user=payload.api_user,
        api_password=payload.api_password,
        location=payload.location,
        description=payload.description,
        is_default=payload.is_default,
        added_by=current_user.id,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    # Test connection immediately
    status = await mt.check_device_connection(_device_to_config(device))
    _apply_status(db, device, status)
    return device


@router.get("/mikrotik/{device_id}", response_model=MikroTikDeviceOut)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = db.query(MikroTikDevice).filter(MikroTikDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.put("/mikrotik/{device_id}", response_model=MikroTikDeviceOut)
async def update_device(
    device_id: int,
    payload: MikroTikDeviceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = db.query(MikroTikDevice).filter(MikroTikDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    update_data = payload.model_dump(exclude_unset=True)

    if update_data.get("is_default"):
        db.query(MikroTikDevice).filter(MikroTikDevice.id != device_id).update({"is_default": False})

    for field, value in update_data.items():
        setattr(device, field, value)

    db.commit()
    db.refresh(device)

    # Re-test if credentials/host changed
    conn_fields = {"host", "port", "use_ssl", "api_user", "api_password"}
    if conn_fields.intersection(update_data.keys()):
        status = await mt.check_device_connection(_device_to_config(device))
        _apply_status(db, device, status)

    return device


@router.delete("/mikrotik/{device_id}")
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = db.query(MikroTikDevice).filter(MikroTikDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.is_default:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the default device. Set another device as default first.",
        )
    db.delete(device)
    db.commit()
    return {"message": f"Device '{device.name}' deleted"}


# ── Connection Test ────────────────────────────────────────────────────────────

@router.post("/mikrotik/{device_id}/test")
async def test_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test connection to a specific device and update its status in the DB."""
    device = db.query(MikroTikDevice).filter(MikroTikDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    status = await mt.check_device_connection(_device_to_config(device))
    _apply_status(db, device, status)

    return {
        "device_id": device_id,
        "name": device.name,
        "host": device.host,
        "connected": status.get("connected", False),
        "identity": device.router_identity,
        "model": device.router_model,
        "version": device.router_version,
        "uptime": device.uptime,
        "cpu_load": device.cpu_load,
        "error": status.get("error"),
    }


@router.post("/mikrotik/{device_id}/set-default")
def set_default_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Set a device as the default (used by existing block/monitor functions)."""
    device = db.query(MikroTikDevice).filter(MikroTikDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    db.query(MikroTikDevice).update({"is_default": False})
    device.is_default = True
    db.commit()
    return {"message": f"'{device.name}' set as default device"}


# ── Topology ──────────────────────────────────────────────────────────────────

@router.post("/mikrotik/refresh-all")
async def refresh_all_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Concurrently test all active devices and update their status."""
    devices = db.query(MikroTikDevice).filter(MikroTikDevice.is_active == True).all()

    async def check_one(device: MikroTikDevice):
        status = await mt.check_device_connection(_device_to_config(device))
        _apply_status(db, device, status)
        return {"id": device.id, "name": device.name, "status": device.last_status}

    results = await asyncio.gather(*[check_one(d) for d in devices], return_exceptions=True)

    return {
        "checked": len(devices),
        "results": [r for r in results if isinstance(r, dict)],
    }


@router.get("/mikrotik/topology/view", response_model=TopologyResponse)
def get_topology(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return topology data for all configured MikroTik devices (uses cached status)."""
    devices = db.query(MikroTikDevice).order_by(
        MikroTikDevice.is_default.desc(), MikroTikDevice.name
    ).all()

    nodes = [
        TopologyNode(
            id=d.id,
            name=d.name,
            host=d.host,
            port=d.port,
            status=d.last_status,
            router_identity=d.router_identity,
            router_model=d.router_model,
            router_version=d.router_version,
            router_board=d.router_board,
            uptime=d.uptime,
            cpu_load=d.cpu_load,
            free_memory=d.free_memory,
            total_memory=d.total_memory,
            interface_count=d.interface_count,
            is_default=d.is_default,
            location=d.location,
            last_checked=d.last_checked,
        )
        for d in devices
    ]

    online = sum(1 for n in nodes if n.status == "online")
    offline = sum(1 for n in nodes if n.status == "offline")
    unknown = sum(1 for n in nodes if n.status == "unknown")

    return TopologyResponse(
        total_devices=len(nodes),
        online_count=online,
        offline_count=offline,
        unknown_count=unknown,
        nodes=nodes,
    )
