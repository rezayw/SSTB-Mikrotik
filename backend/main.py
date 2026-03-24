from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base, SessionLocal
from routers import auth, blocklist, threats, dashboard
from routers import mikrotik_monitor, whitelist, settings
import mikrotik as mt
import logging
import asyncio
import json
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create tables
Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load default MikroTik device from DB on startup."""
    try:
        from models import MikroTikDevice
        db = SessionLocal()
        try:
            default = db.query(MikroTikDevice).filter(
                MikroTikDevice.is_default == True,
                MikroTikDevice.is_active == True,
            ).first()
            if default:
                mt.set_default_device({
                    "host": default.host,
                    "port": default.port,
                    "use_ssl": default.use_ssl,
                    "api_user": default.api_user,
                    "api_password": default.api_password,
                })
                logger.info(f"[Startup] Loaded default MikroTik device: {default.name} ({default.host})")
            else:
                logger.warning("[Startup] No default MikroTik device in DB. Add one via Settings tab.")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"[Startup] Failed to load default device: {e}")
    yield


app = FastAPI(
    title="SSTB — Smart Security & Threat Blocker",
    description="Sistem keamanan proaktif MikroTik berbasis threat intelligence",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
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
app.include_router(mikrotik_monitor.router)
app.include_router(whitelist.router)
app.include_router(settings.router)


# ── WebSocket Live Feed ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.append(ws)
        logger.info(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active_connections:
            self.active_connections.remove(ws)
        logger.info(f"[WS] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """Real-time attack event feed via WebSocket."""
    await ws_manager.connect(websocket)
    try:
        # Send a welcome ping
        await websocket.send_json({"type": "connected", "message": "SSTB live feed connected"})
        while True:
            # Keep-alive: wait for client ping
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except (WebSocketDisconnect, asyncio.TimeoutError):
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"[WS] Error: {e}")
        ws_manager.disconnect(websocket)


# Expose broadcast for use from other modules
app.state.ws_manager = ws_manager


@app.get("/")
def root():
    return {"name": "SSTB API", "version": "2.0.0", "status": "running"}


@app.get("/health")
def health():
    return {"status": "ok"}
