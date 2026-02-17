from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.log_analyzer import log_analyzer

router = APIRouter()

class RuntimeScanRequest(BaseModel):
    log_source: str

@router.get("/scan")
def runtime_scan_status():
    return {
        "module": "Runtime Log Analyzer",
        "status": "connected",
        "alerts": [],
        "message": "Use POST method to perform actual scan"
    }

@router.post("/scan")
def runtime_scan(request: RuntimeScanRequest):
    try:
        analyser = log_analyzer(request.log_source)
        alerts = analyser.analyze_logs()
        return {
            "module": "Runtime Log Analyzer",
            "status": "success",
            "log_source": request.log_source,
            "alert_count": len(alerts),
            "alerts": alerts
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Log file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
