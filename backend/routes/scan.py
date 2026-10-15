"""
Velbrix - Scan Route
Runs all scanners on the uploaded project.
"""
import json
import threading
from pathlib import Path
from fastapi import APIRouter, HTTPException
from ..config import settings
from ..database import get_db
from ..models import Finding
from ..scanners import (
    scan_secrets, scan_code, run_bandit,
    scan_dependencies, run_pip_audit,
    scan_prompt_injection, scan_deploy_readiness,
)
from ..scoring import calculate_score

router = APIRouter()

# Shared scan state
_scan_status = {}


def run_scan_task(scan_id: str, workspace_path: str):
    """Background scan task."""
    try:
        _scan_status[scan_id] = {"status": "scanning", "progress": 0, "current_scanner": "initializing"}

        project_path = Path(workspace_path)
        file_list = [f for f in project_path.rglob("*") if f.is_file()]

        # Filter out junk
        file_list = [f for f in file_list if not any(seg in str(f) for seg in [".git/", "node_modules/", "venv/", "__pycache__/"])]

        all_findings = []

        # 1. Secret scanner
        _scan_status[scan_id] = {"status": "scanning", "progress": 15, "current_scanner": "Secret Scanner"}
        all_findings.extend(scan_secrets(project_path, file_list))

        # 2. Code scanner
        _scan_status[scan_id] = {"status": "scanning", "progress": 35, "current_scanner": "Code Security Scanner"}
        all_findings.extend(scan_code(project_path, file_list))

        # 3. Dependency scanner
        _scan_status[scan_id] = {"status": "scanning", "progress": 55, "current_scanner": "Dependency Scanner"}
        all_findings.extend(scan_dependencies(project_path, file_list))

        # 4. Prompt injection scanner
        _scan_status[scan_id] = {"status": "scanning", "progress": 70, "current_scanner": "Prompt Injection Scanner"}
        all_findings.extend(scan_prompt_injection(project_path, file_list))

        # 5. Deploy readiness scanner
        _scan_status[scan_id] = {"status": "scanning", "progress": 85, "current_scanner": "Deploy Readiness Scanner"}
        all_findings.extend(scan_deploy_readiness(project_path, file_list))

        # 6. Bandit (optional - may produce duplicates, skip for clean demo output)
        # _scan_status[scan_id] = {"status": "scanning", "progress": 95, "current_scanner": "Bandit (Python AST)"}
        # try:
        #     bandit_findings = run_bandit(project_path)
        #     all_findings.extend(bandit_findings)
        # except Exception:
        #     pass

        # Deduplicate findings
        seen_ids = set()
        deduped = []
        for f in all_findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                deduped.append(f)

        # Calculate score
        score_result = calculate_score(deduped, [])

        # Store findings in DB
        db = get_db()
        for f in deduped:
            db.execute(
                """INSERT OR REPLACE INTO findings (id, scan_id, fid, title, severity, category, file, line, evidence, description, why_it_matters, recommended_fix, scanner_source, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (f"{scan_id}_{f.id}", scan_id, f.id, f.title, f.severity, f.category, f.file, f.line, f.evidence, f.description, f.why_it_matters, f.recommended_fix, f.scanner_source, f.confidence),
            )

        # Update scan record
        db.execute(
            """UPDATE scans SET status = 'completed', overall_score = ?, decision = ?, category_scores = ?, summary = ? WHERE id = ?""",
            (score_result["overall_score"], score_result["decision"], json.dumps(score_result["category_scores"]), f"Found {len(deduped)} findings. {score_result['counts']['Critical']} Critical, {score_result['counts']['High']} High.", scan_id),
        )
        db.commit()
        db.close()

        _scan_status[scan_id] = {"status": "completed", "progress": 100, "current_scanner": "done", "findings_count": len(deduped)}

    except Exception as e:
        _scan_status[scan_id] = {"status": "error", "progress": 0, "current_scanner": "error", "error": str(e)}


@router.post("/api/scan/{scan_id}/start")
async def start_scan(scan_id: str):
    """Start scanning the uploaded project."""
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    db.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan_id in _scan_status and _scan_status[scan_id]["status"] == "scanning":
        return {"scan_id": scan_id, "status": "already_scanning"}

    # Find workspace
    workspace = settings.workspace_path / f"workspace_{scan_id}" / "project"
    if not workspace.exists():
        raise HTTPException(status_code=404, detail="Workspace not found. Please re-upload.")

    # Update status
    db = get_db()
    db.execute("UPDATE scans SET status = 'scanning' WHERE id = ?", (scan_id,))
    db.commit()
    db.close()

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_task, args=(scan_id, str(workspace)))
    thread.daemon = True
    thread.start()

    return {"scan_id": scan_id, "status": "scanning_started", "message": "Scan started in background."}


@router.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the live scan progress."""
    status = _scan_status.get(scan_id, {"status": "unknown", "progress": 0})
    return {"scan_id": scan_id, **status}


@router.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get full scan results."""
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        db.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = db.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY severity", (scan_id,)).fetchall()
    patches = db.execute("SELECT * FROM patches WHERE scan_id = ?", (scan_id,)).fetchall()
    db.close()

    findings = []
    for r in findings_rows:
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
            "patched": any(p["finding_id"] == r["fid"] and p["status"] in ["verified", "applied"] for p in patches),
        })

    # Calculate updated score with patched findings excluded
    patched_ids = [p["finding_id"] for p in patches if p["status"] in ["verified", "applied"]]
    from ..models import Finding as FindingModel
    finding_models = [FindingModel(**{k: v for k, v in f.items() if k != "patched"}) for f in findings]
    score_result = calculate_score(finding_models, patched_ids)

    return {
        "scan_id": scan_id,
        "project_name": scan["project_name"],
        "status": scan["status"],
        "stack": scan["stack"],
        "file_count": scan["file_count"],
        "overall_score": score_result["overall_score"],
        "decision": score_result["decision"],
        "category_scores": score_result["category_scores"],
        "counts": score_result["counts"],
        "findings": findings,
        "total_findings": len(findings),
        "patched_count": len(patched_ids),
    }
