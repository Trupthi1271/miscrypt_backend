from fastapi import FastAPI
from app.api.static_scan import router as static_router

app = FastAPI()

@app.get("/")
def root():
    return {"status": "MisCrypt backend running"}

app.include_router(static_router)
