from fastapi import APIRouter
from app.core.static_scanner import static_scan

router = APIRouter()

@router.get("/static-scan")
def run_static_scan(url: str):
    return static_scan(url)
