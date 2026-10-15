"""
Velbrix - Main FastAPI Application
Build fast. Verify before you ship.

Authorization-first security and deploy-readiness platform for AI-generated apps.
"""
import os
import sys
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure local imports work
sys.path.insert(0, str(Path(__file__).parent))

from backend.database import init_db
from backend.config import settings
from backend.ai_providers import ai_manager
from backend.routes import (
    upload_router, scan_router, findings_router, fixme_router,
    agent_guard_router, session_guard_router, report_router,
)

# Initialize database
init_db()

app = FastAPI(
    title="Velbrix",
    description="Build fast. Verify before you ship. - Authorization-first security platform",
    version="1.0.0",
)

# CORS - allow local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(upload_router)
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(fixme_router)
app.include_router(agent_guard_router)
app.include_router(session_guard_router)
app.include_router(report_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "app": "Velbrix", "version": "1.0.0"}


@app.get("/api/ai/status")
async def ai_status():
    return ai_manager.get_status()


# Serve static frontend
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    async def root():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/dashboard")
    async def dashboard_page():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/scan/{scan_id}")
    async def scan_page(scan_id: str):
        return FileResponse(str(static_dir / "index.html"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("VELBRIX_PORT", "8000"))
    host = os.environ.get("VELBRIX_HOST", "0.0.0.0")
    print(f"""
================================================
  Velbrix - Build fast. Verify before you ship.
  Authorized testing only | Synthetic demo data
================================================
  Running on http://{host}:{port}
  Demo ready: /demo/vibebank
================================================
""")
    uvicorn.run(app, host=host, port=port)
