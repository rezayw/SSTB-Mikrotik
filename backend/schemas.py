from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime


# Auth schemas
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


# BlockedIP schemas
class BlockedIPCreate(BaseModel):
    address: str
    reason: Optional[str] = None
    comment: Optional[str] = None
    source: str = "manual"
    expires_hours: Optional[int] = 168  # 7 days default


class BlockedIPOut(BaseModel):
    id: int
    address: str
    threat_score: float
    reason: Optional[str]
    source: Optional[str]
    comment: Optional[str]
    country: Optional[str]
    asn: Optional[str]
    blocked_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    synced_to_mikrotik: bool

    class Config:
        from_attributes = True


# AttackLog schemas
class AttackLogOut(BaseModel):
    id: int
    source_ip: str
    target_port: Optional[int]
    protocol: Optional[str]
    attack_type: Optional[str]
    threat_score: float
    status: str
    country: Optional[str]
    detected_at: datetime

    class Config:
        from_attributes = True


# CVE schemas
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


# Dashboard stats schema
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


# Syslog ingestion schema
class SyslogEvent(BaseModel):
    source_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = "tcp"
    attack_type: Optional[str] = "unknown"
    raw_log: Optional[str] = None


# IP scan result
class IPScanResult(BaseModel):
    ip: str
    threat_score: float
    is_malicious: bool
    virustotal_score: float
    alienvault_score: float
    threatfox_score: float
    sources: List[str]
    details: dict
