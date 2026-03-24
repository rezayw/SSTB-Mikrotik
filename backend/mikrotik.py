import httpx
from typing import Optional
from config import settings
import logging

logger = logging.getLogger(__name__)

MIKROTIK_ADDRESS_LIST = "SSTB-Blacklist"
MIKROTIK_WHITELIST = "SSTB-Whitelist"

# Module-level default device config — set at startup or when default device changes
_default_device_config: Optional[dict] = None


def set_default_device(config: dict):
    """Set the active default MikroTik device config (called from startup/settings)."""
    global _default_device_config
    _default_device_config = config
    logger.info(f"[MikroTik] Default device set: {config.get('host')}:{config.get('port')}")


def get_default_device_config() -> Optional[dict]:
    return _default_device_config


async def get_mikrotik_client() -> httpx.AsyncClient:
    """Return an HTTP client for the default MikroTik device (kept for compatibility)."""
    return _get_client()


def make_client_for(device: dict) -> httpx.AsyncClient:
    """Create an httpx client for a specific MikroTik device config dict."""
    scheme = "https" if device.get("use_ssl", True) else "http"
    host = device["host"]
    port = device.get("port", 443)
    base_url = f"{scheme}://{host}:{port}"
    return httpx.AsyncClient(
        base_url=base_url,
        auth=(device["api_user"], device["api_password"]),
        verify=False,
        timeout=10.0,
    )


async def check_device_connection(device: dict) -> dict:
    """Test connection to a specific device. Returns detailed status dict."""
    async with make_client_for(device) as client:
        try:
            resource_resp = await client.get("/rest/system/resource")
            resource_resp.raise_for_status()
            resource = resource_resp.json()

            identity_resp = await client.get("/rest/system/identity")
            identity = identity_resp.json() if identity_resp.status_code == 200 else {}

            iface_resp = await client.get("/rest/interface")
            iface_count = len(iface_resp.json()) if iface_resp.status_code == 200 else None

            return {
                "connected": True,
                "identity": identity.get("name", ""),
                "model": resource.get("board-name", ""),
                "version": resource.get("version", ""),
                "board": resource.get("platform", ""),
                "uptime": resource.get("uptime", ""),
                "cpu_load": int(resource.get("cpu-load", 0)),
                "free_memory": int(resource.get("free-memory", 0)),
                "total_memory": int(resource.get("total-memory", 0)),
                "interface_count": iface_count,
            }
        except Exception as e:
            logger.error(f"[MikroTik] Device {device.get('host')} unreachable: {e}")
            return {"connected": False, "error": str(e)}


# ── Blocklist ──────────────────────────────────────────────────────────────────

async def block_ip(ip: str, comment: str = "", timeout: str = "7d") -> dict:
    """Add IP to MikroTik SSTB-Blacklist address list."""
    async with _get_client() as client:
        payload = {
            "list": MIKROTIK_ADDRESS_LIST,
            "address": ip,
            "comment": comment or "Blocked by SSTB",
        }
        if timeout:
            payload["timeout"] = timeout
        try:
            response = await client.put("/rest/ip/firewall/address-list", json=payload)
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
    async with _get_client() as client:
        try:
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
            del_response = await client.delete(f"/rest/ip/firewall/address-list/{entry_id}")
            del_response.raise_for_status()
            logger.info(f"[MikroTik] Unblocked IP: {ip}")
            return {"success": True}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to unblock {ip}: {e}")
            return {"success": False, "error": str(e)}


async def get_blocklist() -> list:
    """Get all IPs in SSTB-Blacklist from MikroTik."""
    async with _get_client() as client:
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


# ── Whitelist ─────────────────────────────────────────────────────────────────

async def whitelist_ip(ip: str, comment: str = "") -> dict:
    """Add IP to MikroTik SSTB-Whitelist address list."""
    async with _get_client() as client:
        payload = {
            "list": MIKROTIK_WHITELIST,
            "address": ip,
            "comment": comment or "Whitelisted by SSTB",
        }
        try:
            response = await client.put("/rest/ip/firewall/address-list", json=payload)
            response.raise_for_status()
            logger.info(f"[MikroTik] Whitelisted IP: {ip}")
            return {"success": True, "data": response.json()}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to whitelist {ip}: {e}")
            return {"success": False, "error": str(e)}


async def remove_whitelist_ip(ip: str) -> dict:
    """Remove IP from MikroTik SSTB-Whitelist."""
    async with _get_client() as client:
        try:
            response = await client.get(
                "/rest/ip/firewall/address-list",
                params={"list": MIKROTIK_WHITELIST, "address": ip},
            )
            response.raise_for_status()
            entries = response.json()
            if not entries:
                return {"success": False, "error": "IP not found in whitelist"}
            entry_id = entries[0].get(".id")
            del_response = await client.delete(f"/rest/ip/firewall/address-list/{entry_id}")
            del_response.raise_for_status()
            return {"success": True}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to remove whitelist {ip}: {e}")
            return {"success": False, "error": str(e)}


# ── System Info ───────────────────────────────────────────────────────────────

async def get_router_info() -> dict:
    """Get MikroTik router information (version, uptime, CPU, memory, etc.)."""
    async with _get_client() as client:
        try:
            response = await client.get("/rest/system/resource")
            response.raise_for_status()
            return {"connected": True, "data": response.json()}
        except Exception as e:
            logger.error(f"[MikroTik] Cannot connect: {e}")
            return {"connected": False, "error": str(e)}


async def get_system_identity() -> dict:
    """Get router hostname/identity."""
    async with _get_client() as client:
        try:
            response = await client.get("/rest/system/identity")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get identity: {e}")
            return {}


async def check_connection() -> bool:
    result = await get_router_info()
    return result.get("connected", False)


# ── Interfaces ────────────────────────────────────────────────────────────────

def _get_client(device: Optional[dict] = None) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient for the given device or the default."""
    if device:
        return make_client_for(device)
    if _default_device_config:
        return make_client_for(_default_device_config)
    if settings.MIKROTIK_API_URL and settings.MIKROTIK_API_USER:
        return httpx.AsyncClient(
            base_url=settings.MIKROTIK_API_URL,
            auth=(settings.MIKROTIK_API_USER, settings.MIKROTIK_API_PASSWORD or ""),
            verify=False,
            timeout=10.0,
        )
    raise RuntimeError(
        "No MikroTik device configured. Add a device via Settings tab in the dashboard."
    )


async def get_interfaces(device: Optional[dict] = None) -> list:
    """Get all network interfaces with traffic statistics."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/interface")
            response.raise_for_status()
            interfaces = response.json()
            # Enrich with traffic stats
            stats_response = await client.get("/rest/interface/print", params={"stats": ""})
            if stats_response.status_code == 200:
                stats = {s.get("name"): s for s in stats_response.json()}
                for iface in interfaces:
                    name = iface.get("name", "")
                    if name in stats:
                        iface.update({
                            "rx-byte": stats[name].get("rx-byte", 0),
                            "tx-byte": stats[name].get("tx-byte", 0),
                            "rx-packet": stats[name].get("rx-packet", 0),
                            "tx-packet": stats[name].get("tx-packet", 0),
                            "rx-error": stats[name].get("rx-error", 0),
                            "tx-error": stats[name].get("tx-error", 0),
                        })
            return interfaces
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get interfaces: {e}")
            return []


async def get_interface_traffic(interface_name: str) -> dict:
    """Get real-time traffic stats for a specific interface."""
    async with _get_client() as client:
        try:
            response = await client.get(
                "/rest/interface",
                params={"name": interface_name},
            )
            response.raise_for_status()
            data = response.json()
            return data[0] if data else {}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get interface traffic: {e}")
            return {}


# ── Firewall Setup ────────────────────────────────────────────────────────────

SSTB_DROP_RULES = [
    {
        "chain": "input",
        "src-address-list": MIKROTIK_ADDRESS_LIST,
        "action": "drop",
        "comment": "SSTB-AutoBlock-Input",
        "place-before": "0",
    },
    {
        "chain": "forward",
        "src-address-list": MIKROTIK_ADDRESS_LIST,
        "action": "drop",
        "comment": "SSTB-AutoBlock-Forward",
    },
    {
        "chain": "forward",
        "dst-address-list": MIKROTIK_ADDRESS_LIST,
        "action": "drop",
        "comment": "SSTB-AutoBlock-Forward-Dst",
    },
]


async def ensure_firewall_rules(client: httpx.AsyncClient) -> dict:
    """Create SSTB drop rules if they don't already exist."""
    created = []
    already_exist = []
    failed = []

    # Fetch existing filter rules
    try:
        resp = await client.get("/rest/ip/firewall/filter")
        resp.raise_for_status()
        existing = resp.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

    existing_comments = {r.get("comment", "") for r in existing}

    for rule in SSTB_DROP_RULES:
        if rule["comment"] in existing_comments:
            already_exist.append(rule["comment"])
            continue
        try:
            payload = {k: v for k, v in rule.items() if k != "place-before"}
            r = await client.put("/rest/ip/firewall/filter", json=payload)
            r.raise_for_status()
            created.append(rule["comment"])
            logger.info(f"[MikroTik] Created firewall rule: {rule['comment']}")
        except Exception as e:
            logger.error(f"[MikroTik] Failed to create rule {rule['comment']}: {e}")
            failed.append(rule["comment"])

    return {
        "success": len(failed) == 0,
        "created": created,
        "already_exist": already_exist,
        "failed": failed,
    }


async def setup_sstb_firewall(device: Optional[dict] = None) -> dict:
    """Ensure all SSTB drop rules exist on a device (default or specific)."""
    if device:
        async with make_client_for(device) as client:
            return await ensure_firewall_rules(client)
    else:
        async with _get_client() as client:
            return await ensure_firewall_rules(client)


# ── Firewall Rules ────────────────────────────────────────────────────────────

async def get_firewall_rules(chain: Optional[str] = None, device: Optional[dict] = None) -> list:
    """Get firewall filter rules. Optionally filter by chain (input/forward/output)."""
    async with _get_client(device) as client:
        try:
            params = {}
            if chain:
                params["chain"] = chain
            response = await client.get("/rest/ip/firewall/filter", params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get firewall rules: {e}")
            return []


async def toggle_firewall_rule(rule_id: str, disabled: bool) -> dict:
    """Enable or disable a firewall rule by ID."""
    async with _get_client() as client:
        try:
            response = await client.patch(
                f"/rest/ip/firewall/filter/{rule_id}",
                json={"disabled": "true" if disabled else "false"},
            )
            response.raise_for_status()
            logger.info(f"[MikroTik] {'Disabled' if disabled else 'Enabled'} firewall rule {rule_id}")
            return {"success": True}
        except Exception as e:
            logger.error(f"[MikroTik] Failed to toggle rule {rule_id}: {e}")
            return {"success": False, "error": str(e)}


async def get_nat_rules(device: Optional[dict] = None) -> list:
    """Get NAT (masquerade/dst-nat) rules."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/ip/firewall/nat")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get NAT rules: {e}")
            return []


async def get_all_address_lists(device: Optional[dict] = None) -> list:
    """Get all address list entries across all lists."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/ip/firewall/address-list")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get address lists: {e}")
            return []


# ── DHCP ─────────────────────────────────────────────────────────────────────

async def get_dhcp_leases(device: Optional[dict] = None) -> list:
    """Get all DHCP server leases (connected devices)."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/ip/dhcp-server/lease")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get DHCP leases: {e}")
            return []


# ── Connections ───────────────────────────────────────────────────────────────

async def get_active_connections(limit: int = 100, device: Optional[dict] = None) -> list:
    """Get active connection tracking entries."""
    async with _get_client(device) as client:
        try:
            response = await client.get(
                "/rest/ip/firewall/connection",
                params={".proplist": "src-address,dst-address,protocol,state,tcp-state"},
            )
            response.raise_for_status()
            connections = response.json()
            return connections[:limit]
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get connections: {e}")
            return []


# ── System Logs ───────────────────────────────────────────────────────────────

async def get_system_logs(count: int = 100, topics: Optional[str] = None, device: Optional[dict] = None) -> list:
    """Get MikroTik system log entries."""
    async with _get_client(device) as client:
        try:
            params: dict = {}
            if topics:
                params["topics"] = topics
            response = await client.get("/rest/log", params=params)
            response.raise_for_status()
            logs = response.json()
            return logs[-count:] if len(logs) > count else logs
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get logs: {e}")
            return []


# ── IP Routes ─────────────────────────────────────────────────────────────────

async def get_ip_routes(device: Optional[dict] = None) -> list:
    """Get IP routing table."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/ip/route")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get routes: {e}")
            return []


# ── IP Addresses ──────────────────────────────────────────────────────────────

async def get_ip_addresses(device: Optional[dict] = None) -> list:
    """Get all configured IP addresses on interfaces."""
    async with _get_client(device) as client:
        try:
            response = await client.get("/rest/ip/address")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[MikroTik] Failed to get IP addresses: {e}")
            return []
