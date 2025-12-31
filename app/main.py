# app/main.py
from fastapi import FastAPI

app = FastAPI(title="MisCrypt Backend")

@app.get("/")
def root():
    return {"status": "MisCrypt backend running"}
