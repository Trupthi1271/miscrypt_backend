from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.tls_scanner import run_tls_scan

router = APIRouter()

class TLSScanRequest(BaseModel):
    domain: str
    port: int = 443

@router.post("/scan")
def tls_scan(request: TLSScanRequest):
    try:
        issues = run_tls_scan(request.domain, request.port)
        return {
            "module": "TLS Scanner",
            "status": "success",
            "domain": request.domain,
            "port": request.port,
            "tls_issues": issues,
            "total_issues": len(issues)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))