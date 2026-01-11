from fastapi import APIRouter

router = APIRouter()

@router.get("/scan")
def runtime_scan_status():
    """GET endpoint for testing - returns basic status"""
    return {
        "module": "Runtime Log Analyzer",
        "status": "connected",
        "alerts": [],
        "message": "Use POST method to perform actual scan"
    }

@router.post("/scan")
def runtime_scan(log_source: str):
    return {
        "module": "Runtime Log Analyzer",
        "status": "connected",
        "alerts": []
    }