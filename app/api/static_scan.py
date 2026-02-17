from fastapi import APIRouter
from app.core.static_scanner import static_scan

router = APIRouter(prefix="/static", tags=["Static Scanner"])


class StaticScanRequest(BaseModel):
    code: Optional[str] = None
    repo_url: Optional[str] = None
    language: str = "python"

@router.post("/scan")
def scan_repo(repo_url: str):
    return static_scan(repo_url)
