from fastapi import FastAPI
from app.api.static_scan import router as static_router
from app.api import runtime_scan

app = FastAPI()

app.include_router(static_router)
# Include runtime scan router at root level (so /scan works directly)
app.include_router(runtime_scan.router, tags=["Runtime Analysis"])

@app.get("/")
def root():
    return {"status": "MisCrypt backend running"}
