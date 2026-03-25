# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import runtime_scan, static_scan, tls_scan
import os

app = FastAPI(title="MisCrypt Backend", version="1.0.0")

# CORS — allow local dev + deployed Vercel frontend
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")
DEFAULT_ORIGINS = [
    "http://localhost:5000",
    "http://localhost:5173",
    "http://127.0.0.1:5000",
    "https://mis-crypt.vercel.app",
    "https://mis-crypt-git-main-hithaankams-projects.vercel.app",
    "https://mis-crypt-26rrwzq7o-hithaankams-projects.vercel.app",
]
origins = [o.strip() for o in ALLOWED_ORIGINS if o.strip()] or DEFAULT_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(runtime_scan.router, prefix="/api/runtime", tags=["Runtime Analysis"])
app.include_router(static_scan.router, prefix="/api/static", tags=["Static Analysis"])
app.include_router(tls_scan.router, prefix="/api/tls", tags=["TLS Analysis"])

@app.get("/")
def root():
    return {"status": "MisCrypt backend running", "version": "1.0.0"}

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "modules": ["static", "tls", "runtime"]}
