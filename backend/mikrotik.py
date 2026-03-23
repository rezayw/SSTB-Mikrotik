import httpx
from typing import Optional
from config import settings
import logging

logger = logging.getLogger(__name__)

MIKROTIK_ADDRESS_LIST = "SSTB-Blacklist"


async def get_mikrotik_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.MIKROTIK_API_URL,
        auth=(settings.MIKROTIK_API_USER, settings.MIKROTIK_API_PASSWORD),
        verify=False,  # MikroTik self-signed cert
        timeout=10.0,
    )


async def block_ip(ip: str, comment: str = "", timeout: str = "7d") -> dict:
    """Add IP to MikroTik SSTB-Blacklist address list."""
    async with await get_mikrotik_client() as client:
        payload = {
            "list": MIKROTIK_ADDRESS_LIST,
            "address": ip,
            "comment": comment or f"Blocked by SSTB",
        }
        if timeout:
            payload["timeout"] = timeout

        try:
            response = await client.post("/rest/ip/firewall/address-list", json=payload)
            response.raise_for_status()
            logger.info(f"[MikroTik] Blocked IP: {ip}")
            return {"success": True, "data": response.json()}
        except httpx.HTTPStatusError as e:
            logger.error(f"[MikroTik] Failed to block {ip}: {e.response.text}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"[MikroTik] Connection error: {e}")
            return {"success": False, "error": str(e)}


async def unblock_ip(ip: str) -> dict:
    """Remove IP from MikroTik SSTB-Blacklist."""
    async with await get_mikrotik_client() as client:
        try:
            # First find the entry ID
            response = await client.get(
                "/rest/ip/firewall/address-list",
                params={"list": MIKROTIK_ADDRESS_LIST, "address": ip},
            )
            response.raise_for_status()
            entries = response.json()

            if not entries:
                return {"success": False, "error": "IP not found in blocklist"}

            entry_id = entries[0].get(".id")
            if not entry_id:
                return {"success": False, "error": "Invalid entry"}

            # Delete by ID
            del_response = await client.delete(f"/rest/ip/firewall/address-list/{entry_id}")
            del_response.raise_for_status()
            logger.info(f"[MikroTik] Unblocked IP: {ip}")
            return {"success": True}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to unblock {ip}: {e}")
            return {"success": False, "error": str(e)}


async def get_blocklist() -> list:
    """Get all IPs in SSTB-Blacklist from MikroTik."""
    async with await get_mikrotik_client() as client:
        try:
            response = await client.get(
                "/rest/ip/firewall/address-list",
                params={"list": MIKROTIK_ADDRESS_LIST},
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get blocklist: {e}")
            return []


async def get_router_info() -> dict:
    """Get MikroTik router information (version, etc.)."""
    async with await get_mikrotik_client() as client:
        try:
            response = await client.get("/rest/system/resource")
            response.raise_for_status()
            return {"connected": True, "data": response.json()}
        except Exception as e:
            logger.error(f"[MikroTik] Cannot connect: {e}")
            return {"connected": False, "error": str(e)}


async def check_connection() -> bool:
    """Quick connectivity check."""
    result = await get_router_info()
    return result.get("connected", False)
