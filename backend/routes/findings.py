"""
Velbrix - Findings Route
"""
from fastapi import APIRouter, HTTPException
from ..database import get_db

router = APIRouter()


@router.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str, severity: str = None, category: str = None, search: str = None):
    """Get findings with optional filters."""
    db = get_db()
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params = [scan_id]

    if severity and severity != "all":
        query += " AND severity = ?"
        params.append(severity)

    if category and category != "all":
        query += " AND category = ?"
        params.append(category)

    if search:
        query += " AND (title LIKE ? OR description LIKE ? OR evidence LIKE ? OR file LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])

    query += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 WHEN 'Info' THEN 5 ELSE 6 END, line"

    rows = db.execute(query, params).fetchall()
    db.close()

    findings = []
    for r in rows:
        findings.append({
            "id": r["fid"],
            "title": r["title"],
            "severity": r["severity"],
            "category": r["category"],
            "file": r["file"],
            "line": r["line"],
            "evidence": r["evidence"],
            "description": r["description"],
            "why_it_matters": r["why_it_matters"],
            "recommended_fix": r["recommended_fix"],
            "scanner_source": r["scanner_source"],
            "confidence": r["confidence"],
        })

    return {"findings": findings, "count": len(findings)}


@router.get("/api/scan/{scan_id}/findings/{finding_id}")
async def get_finding_detail(scan_id: str, finding_id: str):
    """Get a single finding with file context."""
    db = get_db()
    row = db.execute("SELECT * FROM findings WHERE scan_id = ? AND fid = ?", (scan_id, finding_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(status_code=404, detail="Finding not found")

    # Try to read the file for context
    file_content = ""
    file_lines = []
    from ..config import settings
    from pathlib import Path
    workspace = settings.workspace_path / f"workspace_{scan_id}" / "project"
    target_file = workspace / row["file"]
    if target_file.exists():
        try:
            file_content = target_file.read_text(encoding="utf-8", errors="ignore")
            file_lines = file_content.splitlines()
        except Exception:
            pass

    db.close()

    # Get context around the finding line
    context_start = max(0, row["line"] - 5)
    context_end = min(len(file_lines), row["line"] + 5)
    context_lines = []
    for i in range(context_start, context_end):
        context_lines.append({"line_number": i + 1, "content": file_lines[i] if i < len(file_lines) else "", "is_finding": (i + 1) == row["line"]})

    return {
        "id": row["fid"],
        "title": row["title"],
        "severity": row["severity"],
        "category": row["category"],
        "file": row["file"],
        "line": row["line"],
        "evidence": row["evidence"],
        "description": row["description"],
        "why_it_matters": row["why_it_matters"],
        "recommended_fix": row["recommended_fix"],
        "scanner_source": row["scanner_source"],
        "confidence": row["confidence"],
        "file_content": file_content,
        "context_lines": context_lines,
    }


@router.get("/api/scan/{scan_id}/categories")
async def get_categories(scan_id: str):
    """Get unique categories and severity counts."""
    db = get_db()
    cats = db.execute("SELECT DISTINCT category FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    sevs = db.execute("SELECT severity, COUNT(*) as count FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,)).fetchall()
    db.close()
    return {
        "categories": [c["category"] for c in cats],
        "severity_counts": {s["severity"]: s["count"] for s in sevs},
    }


@router.get("/api/scan/{scan_id}/filetree")
async def get_file_tree(scan_id: str):
    """Get the project file tree."""
    from ..config import settings
    from pathlib import Path
    workspace = settings.workspace_path / f"workspace_{scan_id}" / "project"
    if not workspace.exists():
        raise HTTPException(status_code=404, detail="Workspace not found")

    tree = []
    for item in sorted(workspace.rglob("*")):
        if any(seg in str(item) for seg in [".git/", "node_modules/", "venv/", "__pycache__/"]):
            continue
        if item.is_file():
            rel = str(item.relative_to(workspace))
            tree.append(rel)

    return {"files": tree}
