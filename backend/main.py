from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base
from routers import auth, blocklist, threats, dashboard
import logging

logging.basicConfig(level=logging.INFO)

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SSTB - Smart Security & Threat Blocker",
    description="Sistem keamanan proaktif MikroTik berbasis threat intelligence",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(blocklist.router)
app.include_router(threats.router)
app.include_router(dashboard.router)


@app.get("/")
def root():
    return {
        "name": "SSTB API",
        "version": "1.0.0",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
