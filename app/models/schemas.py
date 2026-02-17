# app/models/schemas.py
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


# ---------- Static Scan ----------
class StaticFinding(BaseModel):
    type: str
    file: str
    severity: Optional[str] = "MEDIUM"


class StaticScanResponse(BaseModel):
    findings: List[StaticFinding]


# ---------- TLS Scan ----------
class TLSIssue(BaseModel):
    issue: str
    detail: Optional[str] = None
    severity: Optional[str] = "MEDIUM"


class TLSScanResponse(BaseModel):
    tls_issues: List[TLSIssue]


# ---------- Runtime Scan ----------
class AttackType(str, Enum):
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
    CIPHER_ENUMERATION = "cipher_enumeration"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"
    ABNORMAL_CONNECTION = "abnormal_connection"
    SSL_STRIPPING = "ssl_stripping"
    CERTIFICATE_PROBING = "certificate_probing"


class RuntimeAlert(BaseModel):
    alert_type: AttackType
    timestamp: datetime
    source_ip: str
    evidence: str
    frequency: int
    severity: str
    confidence_score: float
    attack_pattern: Optional[str] = None
    additional_context: Optional[Dict[str, Any]] = None


class LogSource(BaseModel):
    source_type: str  # "file", "stream", "remote"
    path_or_url: str
    log_format: Optional[str] = "auto"  # "nginx", "apache", "custom", "auto"
    credentials: Optional[Dict[str, str]] = None


class RuntimeScanRequest(BaseModel):
    log_sources: List[LogSource]
    scan_duration_hours: Optional[int] = 24
    enable_real_time: Optional[bool] = False
    custom_patterns: Optional[List[str]] = None


class RuntimeScanResponse(BaseModel):
    scan_id: str
    alerts: List[RuntimeAlert]
    scan_summary: Dict[str, Any]
    exploitability_indicators: Dict[str, int]
    recommendations: List[str]


# ---------- Correlation ----------
class RiskScore(BaseModel):
    risk_score: int
    severity: str


# ---------- Log Analysis Models ----------
class LogEntry(BaseModel):
    timestamp: datetime
    source_ip: str
    request_line: str
    status_code: int
    user_agent: Optional[str] = None
    ssl_protocol: Optional[str] = None
    ssl_cipher: Optional[str] = None
    error_message: Optional[str] = None
    raw_log: str


class AttackPattern(BaseModel):
    pattern_name: str
    regex_pattern: str
    severity: str
    description: str
