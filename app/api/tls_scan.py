from fastapi import APIRouter
from app.core.tls_scanner import full_tls_scan

router = APIRouter()

@router.post("/scan")
def tls_scan(domain: str):
    return {
        "module": "TLS Scanner",
        "result": full_tls_scan(domain)
    }
