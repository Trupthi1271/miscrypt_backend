from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel
from app.core.log_analyzer import log_analyzer
import tempfile
import os

router = APIRouter()

class RuntimeScanRequest(BaseModel):
    log_source: str

@router.get("/scan")
def runtime_scan_status():
    return {"module": "Runtime Log Analyzer", "status": "connected", "message": "Use POST to scan"}

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

@router.post("/scan/upload")
async def runtime_scan_upload(file: UploadFile = File(...)):
    tmp_path = None
    try:
        content = await file.read()
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.log', delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        analyser = log_analyzer(tmp_path)
        alerts = analyser.analyze_logs()
        return {
            "module": "Runtime Log Analyzer",
            "status": "success",
            "log_source": file.filename,
            "alert_count": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
