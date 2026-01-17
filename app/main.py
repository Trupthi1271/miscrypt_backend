# app/main.py
from fastapi import FastAPI
from app.api import runtime_scan

app = FastAPI(title="MisCrypt Backend")

# Include runtime scan router at root level (so /scan works directly)
app.include_router(runtime_scan.router, tags=["Runtime Analysis"])

@app.get("/")
def root():
    return {"status": "MisCrypt backend running"}
