from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.core.static_scanner import run_static_scan, scan_git_repository

router = APIRouter()

class StaticScanRequest(BaseModel):
    code: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "python"

@router.post("/scan")
def static_scan(request: StaticScanRequest):
    try:
        # Check if it's a Git repository scan or code scan
        if request.repo_url:
            findings = scan_git_repository(request.repo_url)
            return {
                "module": "Static Crypto Scanner",
                "status": "success",
                "scan_type": "repository",
                "repo_url": request.repo_url,
                "findings": findings,
                "total_issues": len(findings)
            }
        elif request.code:
            findings = run_static_scan(request.code, request.language)
            return {
                "module": "Static Crypto Scanner",
                "status": "success",
                "scan_type": "code",
                "language": request.language,
                "findings": findings,
                "total_issues": len(findings)
            }
        else:
            raise HTTPException(status_code=400, detail="Either 'code' or 'repo_url' must be provided")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
