from fastapi import APIRouter, HTTPException
from app.core.log_analyzer import log_analyzer

router = APIRouter()

@router.get("/scan")
def runtime_scan_status():
    return {
        "module": "Runtime Log Analyzer",
        "status": "connected",
        "alerts": [],
        "message": "Use POST method to perform actual scan"
    }

@router.post("/scan")
def runtime_scan(log_source: str):
    try:
        analyser = log_analyzer(log_source)
        alerts = analyser.analyze_logs()
        print(alerts)
        return {
            "module": "Runtime Log Analyzer",
            "status": "connected",
            "cnt": len(alerts),
            "alerts": alerts
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="log file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
