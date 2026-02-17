# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import runtime_scan, static_scan, tls_scan

app = FastAPI(title="MisCrypt Backend", version="1.0.0")

# CORS configuration for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000", "http://localhost:5173", "http://127.0.0.1:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all API routers
app.include_router(runtime_scan.router, prefix="/api/runtime", tags=["Runtime Analysis"])
app.include_router(static_scan.router, prefix="/api/static", tags=["Static Analysis"])
app.include_router(tls_scan.router, prefix="/api/tls", tags=["TLS Analysis"])

@app.get("/")
def root():
    return {"status": "MisCrypt backend running", "version": "1.0.0"}

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "modules": ["static", "tls", "runtime"]}
