# app/models/schemas.py
from pydantic import BaseModel
from typing import List, Optional


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
class RuntimeAlert(BaseModel):
    alert_type: str
    evidence: Optional[str] = None


class RuntimeScanResponse(BaseModel):
    alerts: List[RuntimeAlert]


# ---------- Correlation ----------
class RiskScore(BaseModel):
    risk_score: int
    severity: str