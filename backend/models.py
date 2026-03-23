from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    address = Column(String(45), unique=True, index=True, nullable=False)
    threat_score = Column(Float, default=0.0)
    reason = Column(String(500))
    source = Column(String(50))  # virustotal, alienvault, threatfox, manual, cisa
    comment = Column(String(500))
    country = Column(String(100))
    asn = Column(String(100))
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
    detected_at = Column(DateTime, default=datetime.utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    virustotal_score = Column(Float, default=0.0)
    alienvault_score = Column(Float, default=0.0)
    threatfox_score = Column(Float, default=0.0)
    total_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    raw_data = Column(Text)  # JSON string
    last_checked = Column(DateTime, default=datetime.utcnow)


class CVEAlert(Base):
    __tablename__ = "cve_alerts"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, index=True)
    description = Column(Text)
    severity = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(Float, default=0.0)
    is_kev = Column(Boolean, default=False)  # Known Exploited Vulnerability
    affected_product = Column(String(200))
    epss_score = Column(Float, default=0.0)  # Exploit Prediction Score
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
