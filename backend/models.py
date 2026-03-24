from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Float, Boolean, Text
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    address = Column(String(45), unique=True, index=True, nullable=False)
    threat_score = Column(Float, default=0.0)
    reason = Column(String(500))
    source = Column(String(50))  # virustotal, alienvault, abuseipdb, threatfox, manual, cisa
    comment = Column(String(500))
    country = Column(String(100))
    country_code = Column(String(5))
    city = Column(String(100))
    isp = Column(String(200))
    asn = Column(String(100))
    threat_categories = Column(String(500))  # comma-separated categories
    is_tor = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    synced_to_mikrotik = Column(Boolean, default=False)


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    target_port = Column(Integer)
    protocol = Column(String(10))
    attack_type = Column(String(100))  # ssh_brute, port_scan, winbox, etc.
    threat_score = Column(Float, default=0.0)
    status = Column(String(20), default="pending")  # pending, blocked, whitelisted, analyzing
    raw_log = Column(Text)
    country = Column(String(100))
    country_code = Column(String(5))
    city = Column(String(100))
    isp = Column(String(200))
    asn = Column(String(100))
    threat_categories = Column(String(500))
    detected_at = Column(DateTime, default=datetime.utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    virustotal_score = Column(Float, default=0.0)
    alienvault_score = Column(Float, default=0.0)
    threatfox_score = Column(Float, default=0.0)
    abuseipdb_score = Column(Float, default=0.0)
    total_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    country = Column(String(100))
    country_code = Column(String(5))
    isp = Column(String(200))
    threat_categories = Column(String(500))
    raw_data = Column(Text)  # Full JSON result
    last_checked = Column(DateTime, default=datetime.utcnow)


class CVEAlert(Base):
    __tablename__ = "cve_alerts"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True)
    description = Column(Text)
    severity = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(Float, default=0.0)
    is_kev = Column(Boolean, default=False)  # Known Exploited Vulnerability (CISA)
    affected_product = Column(String(200))
    epss_score = Column(Float, default=0.0)  # Exploit Prediction Scoring System
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)


class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    address = Column(String(45), unique=True, index=True, nullable=False)
    reason = Column(String(500))
    comment = Column(String(500))
    added_by = Column(String(100))
    synced_to_mikrotik = Column(Boolean, default=False)
    added_at = Column(DateTime, default=datetime.utcnow)


class GeoCache(Base):
    __tablename__ = "geo_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    country = Column(String(100))
    country_code = Column(String(5))
    region = Column(String(100))
    city = Column(String(100))
    isp = Column(String(200))
    org = Column(String(200))
    asn = Column(String(100))
    lat = Column(Float, default=0.0)
    lon = Column(Float, default=0.0)
    timezone = Column(String(100))
    is_proxy = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)
    cached_at = Column(DateTime, default=datetime.utcnow)


class MikroTikDevice(Base):
    __tablename__ = "mikrotik_devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)            # e.g. "Router Kantor Utama"
    host = Column(String(255), nullable=False)             # IP or hostname
    port = Column(Integer, default=443)
    use_ssl = Column(Boolean, default=True)
    api_user = Column(String(100), nullable=False)
    api_password = Column(String(255), nullable=False)    # stored plaintext; DB is internal network
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)           # only one device can be default
    location = Column(String(200), nullable=True)         # physical location description
    description = Column(String(500), nullable=True)
    # Status fields updated on connection check
    last_checked = Column(DateTime, nullable=True)
    last_status = Column(String(20), default="unknown")   # online, offline, unknown
    router_identity = Column(String(100), nullable=True)
    router_model = Column(String(100), nullable=True)
    router_version = Column(String(50), nullable=True)
    router_board = Column(String(100), nullable=True)
    uptime = Column(String(50), nullable=True)
    cpu_load = Column(Integer, nullable=True)
    free_memory = Column(BigInteger, nullable=True)
    total_memory = Column(BigInteger, nullable=True)
    interface_count = Column(Integer, nullable=True)
    added_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
