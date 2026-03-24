from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List, Any
from datetime import datetime
import ipaddress


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut


# ── BlockedIP ─────────────────────────────────────────────────────────────────

class BlockedIPCreate(BaseModel):
    address: str
    reason: Optional[str] = None
    comment: Optional[str] = None
    source: str = "manual"
    expires_hours: Optional[int] = 168  # 7 days default

    @field_validator("address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v

    @field_validator("expires_hours")
    @classmethod
    def validate_expires(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError("expires_hours must be positive")
        return v


class BlockedIPOut(BaseModel):
    id: int
    address: str
    threat_score: float
    reason: Optional[str]
    source: Optional[str]
    comment: Optional[str]
    country: Optional[str]
    country_code: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    threat_categories: Optional[str]
    is_tor: bool
    is_proxy: bool
    blocked_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    synced_to_mikrotik: bool

    class Config:
        from_attributes = True


# ── AttackLog ─────────────────────────────────────────────────────────────────

class AttackLogOut(BaseModel):
    id: int
    source_ip: str
    target_port: Optional[int]
    protocol: Optional[str]
    attack_type: Optional[str]
    threat_score: float
    status: str
    country: Optional[str]
    country_code: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    threat_categories: Optional[str]
    detected_at: datetime

    class Config:
        from_attributes = True


# ── CVE ───────────────────────────────────────────────────────────────────────

class CVEAlertOut(BaseModel):
    id: int
    cve_id: str
    description: Optional[str]
    severity: Optional[str]
    cvss_score: float
    is_kev: bool
    affected_product: Optional[str]
    epss_score: float
    published_date: Optional[datetime]

    class Config:
        from_attributes = True


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_blocked: int
    blocked_today: int
    threats_detected: int
    threats_today: int
    active_cve_alerts: int
    critical_cve_count: int
    mikrotik_connected: bool
    auto_block_enabled: bool
    last_sync: Optional[datetime]


# ── Syslog Ingest ─────────────────────────────────────────────────────────────

class SyslogEvent(BaseModel):
    source_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = "tcp"
    attack_type: Optional[str] = "unknown"
    raw_log: Optional[str] = None


# ── Threat Intel ──────────────────────────────────────────────────────────────

class GeoInfo(BaseModel):
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    lat: float = 0.0
    lon: float = 0.0
    timezone: str = ""
    is_proxy: bool = False
    is_hosting: bool = False


class VirusTotalDetail(BaseModel):
    score: float
    detected: bool
    malicious_engines: int = 0
    suspicious_engines: int = 0
    total_engines: int = 0
    flagged_engines: List[str] = []
    reputation: int = 0
    network: str = ""


class AlienVaultDetail(BaseModel):
    score: float
    detected: bool
    pulse_count: int = 0
    tags: List[str] = []
    malware_families: List[str] = []
    adversaries: List[str] = []


class ThreatFoxDetail(BaseModel):
    score: float
    detected: bool
    ioc_count: int = 0
    malware_names: List[str] = []
    threat_types: List[str] = []
    avg_confidence: float = 0.0


class AbuseIPDBDetail(BaseModel):
    score: float
    detected: bool
    confidence: int = 0
    total_reports: int = 0
    distinct_users: int = 0
    isp: str = ""
    domain: str = ""
    usage_type: str = ""
    is_tor: bool = False
    categories: List[str] = []
    last_reported: str = ""


class IPScanResult(BaseModel):
    ip: str
    threat_score: float
    is_malicious: bool
    # Per-source scores
    virustotal_score: float
    alienvault_score: float
    threatfox_score: float
    abuseipdb_score: float = 0.0
    # Classification
    threat_categories: List[str] = []
    threat_primary: str = "unknown"
    sources: List[str]
    # Geolocation
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""
    is_tor: bool = False
    is_proxy: bool = False
    geo: Optional[GeoInfo] = None
    # Per-source details
    virustotal: Optional[VirusTotalDetail] = None
    alienvault: Optional[AlienVaultDetail] = None
    threatfox: Optional[ThreatFoxDetail] = None
    abuseipdb: Optional[AbuseIPDBDetail] = None
    details: dict = {}


# ── Whitelist ─────────────────────────────────────────────────────────────────

class WhitelistCreate(BaseModel):
    address: str
    reason: Optional[str] = None
    comment: Optional[str] = None

    @field_validator("address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class WhitelistOut(BaseModel):
    id: int
    address: str
    reason: Optional[str]
    comment: Optional[str]
    added_by: Optional[str]
    synced_to_mikrotik: bool
    added_at: datetime

    class Config:
        from_attributes = True


# ── MikroTik Monitor ─────────────────────────────────────────────────────────

class InterfaceInfo(BaseModel):
    name: str
    type: str = ""
    mtu: int = 1500
    running: bool = False
    disabled: bool = False
    rx_byte: int = 0
    tx_byte: int = 0
    rx_packet: int = 0
    tx_packet: int = 0
    mac_address: str = ""
    comment: str = ""


class FirewallRule(BaseModel):
    id: str = ""
    chain: str = ""
    action: str = ""
    src_address: str = ""
    dst_address: str = ""
    protocol: str = ""
    dst_port: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    comment: str = ""
    disabled: bool = False
    bytes: int = 0
    packets: int = 0


class DHCPLease(BaseModel):
    address: str = ""
    mac_address: str = ""
    host_name: str = ""
    status: str = ""
    expires_after: str = ""
    comment: str = ""


class SystemLogEntry(BaseModel):
    time: str = ""
    topics: str = ""
    message: str = ""


# ── MikroTik Device Management ────────────────────────────────────────────────

class MikroTikDeviceCreate(BaseModel):
    name: str
    host: str
    port: int = 443
    use_ssl: bool = True
    api_user: str
    api_password: str
    location: Optional[str] = None
    description: Optional[str] = None
    is_default: bool = False


class MikroTikDeviceUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    use_ssl: Optional[bool] = None
    api_user: Optional[str] = None
    api_password: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


class MikroTikDeviceOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    use_ssl: bool
    api_user: str
    is_active: bool
    is_default: bool
    location: Optional[str]
    description: Optional[str]
    last_checked: Optional[datetime]
    last_status: str
    router_identity: Optional[str]
    router_model: Optional[str]
    router_version: Optional[str]
    router_board: Optional[str]
    uptime: Optional[str]
    cpu_load: Optional[int]
    free_memory: Optional[int]
    total_memory: Optional[int]
    interface_count: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class TopologyNode(BaseModel):
    id: int
    name: str
    host: str
    port: int
    status: str
    router_identity: Optional[str]
    router_model: Optional[str]
    router_version: Optional[str]
    router_board: Optional[str]
    uptime: Optional[str]
    cpu_load: Optional[int]
    free_memory: Optional[int]
    total_memory: Optional[int]
    interface_count: Optional[int]
    is_default: bool
    location: Optional[str]
    last_checked: Optional[datetime]


class TopologyResponse(BaseModel):
    sstb_version: str = "2.0.0"
    total_devices: int
    online_count: int
    offline_count: int
    unknown_count: int
    nodes: List[TopologyNode]
