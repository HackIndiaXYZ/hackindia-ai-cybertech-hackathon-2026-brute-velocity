"""
Velbrix - Upload Route
"""
import uuid
import zipfile
import shutil
import json
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from typing import Optional
from ..config import settings
from ..database import get_db

router = APIRouter()

# In-memory scan state (for demo simplicity)
_scan_states = {}


@router.post("/api/upload")
async def upload_project(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload a ZIP file for scanning."""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported.")

    scan_id = str(uuid.uuid4())[:8]
    workspace = settings.workspace_path / f"workspace_{scan_id}"
    workspace.mkdir(parents=True, exist_ok=True)

    # Save the uploaded zip
    zip_path = workspace / "upload.zip"
    with open(zip_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # Extract
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(workspace / "project")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file.")

    # Remove the zip to save space
    zip_path.unlink(missing_ok=True)

    # Detect stack and count files
    project_dir = workspace / "project"
    # Handle case where zip wraps everything in a single top-level folder
    entries = list(project_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        project_dir = entries[0]

    file_list = [f for f in project_dir.rglob("*") if f.is_file()]
    stack = detect_stack(project_dir, file_list)

    # Store scan record
    db = get_db()
    db.execute(
        """INSERT INTO scans (id, project_name, created_at, status, stack, file_count, overall_score, decision, category_scores, summary)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, file.filename.replace(".zip", ""), datetime.now().isoformat(),
         "uploaded", stack, len(file_list), 0, "PENDING", "{}", "Project uploaded successfully."),
    )
    db.commit()
    db.close()

    _scan_states[scan_id] = {
        "workspace": str(project_dir),
        "status": "uploaded",
    }

    return {
        "scan_id": scan_id,
        "project_name": file.filename.replace(".zip", ""),
        "file_count": len(file_list),
        "stack": stack,
        "status": "uploaded",
        "message": "Project uploaded. Click 'Start Scan' to begin.",
    }


@router.post("/api/upload/demo")
async def load_demo_project(background_tasks: BackgroundTasks):
    """Load the bundled VibeBank demo project."""
    demo_src = settings.demo_project_path
    if not demo_src.exists():
        raise HTTPException(status_code=404, detail="Demo project not found.")

    scan_id = str(uuid.uuid4())[:8]
    workspace = settings.workspace_path / f"workspace_{scan_id}"
    workspace.mkdir(parents=True, exist_ok=True)

    # Copy demo project
    project_dir = workspace / "project"
    shutil.copytree(demo_src, project_dir)

    file_list = [f for f in project_dir.rglob("*") if f.is_file()]
    stack = detect_stack(project_dir, file_list)

    db = get_db()
    db.execute(
        """INSERT INTO scans (id, project_name, created_at, status, stack, file_count, overall_score, decision, category_scores, summary)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "VibeBank Demo", datetime.now().isoformat(),
         "uploaded", stack, len(file_list), 0, "PENDING", "{}", "Demo project loaded."),
    )
    db.commit()
    db.close()

    _scan_states[scan_id] = {
        "workspace": str(project_dir),
        "status": "uploaded",
    }

    return {
        "scan_id": scan_id,
        "project_name": "VibeBank Demo",
        "file_count": len(file_list),
        "stack": stack,
        "status": "uploaded",
        "message": "VibeBank demo project loaded. Click 'Start Scan' to begin.",
    }


@router.get("/api/scans")
async def list_scans():
    """List all scans."""
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    db.close()
    return [dict(r) for r in rows]


@router.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details."""
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.close()
    return dict(row)


def detect_stack(project_dir: Path, file_list: list) -> str:
    """Detect the project tech stack."""
    stacks = []
    if any(f.name == "requirements.txt" for f in file_list):
        stacks.append("Python")
    if any(f.name == "package.json" for f in file_list):
        stacks.append("Node.js")
    if any(f.name == "manage.py" for f in file_list):
        stacks.append("Django")
    if any(f.name == "app.py" or "flask" in f.name.lower() for f in file_list):
        if "Python" not in stacks:
            stacks.append("Flask")
    if any(f.name == "pom.xml" for f in file_list):
        stacks.append("Java")
    if any(f.name == "go.mod" for f in file_list):
        stacks.append("Go")
    if any(f.name == "Cargo.toml" for f in file_list):
        stacks.append("Rust")
    return " + ".join(stacks) if stacks else "Unknown"
