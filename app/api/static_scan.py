from fastapi import APIRouter

router = APIRouter()

@router.post("/scan")
def static_scan(repo_url: str):
    return {
        "module": "Static Crypto Scanner",
        "status": "connected",
        "findings": []
    }