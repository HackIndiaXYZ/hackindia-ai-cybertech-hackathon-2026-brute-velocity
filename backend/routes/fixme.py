"""
Velbrix - FixMe Space Route
"""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from ..database import get_db
from ..config import settings
from ..models import Finding
from ..patch_engine import generate_patch, apply_patch_to_temp, verify_patch, get_patch_history

router = APIRouter()


@router.post("/api/fixme/{scan_id}/generate/{finding_id}")
async def generate_finding_patch(scan_id: str, finding_id: str):
    """Generate a secure patch for a finding."""
    db = get_db()
    row = db.execute("SELECT * FROM findings WHERE scan_id = ? AND fid = ?", (scan_id, finding_id)).fetchone()
    if not row:
        db.close()
        raise HTTPException(status_code=404, detail="Finding not found")

    # Read the file content
    workspace = settings.workspace_path / f"workspace_{scan_id}" / "project"
    target_file = workspace / row["file"]
    file_content = ""
    if target_file.exists():
        file_content = target_file.read_text(encoding="utf-8", errors="ignore")
    db.close()

    finding = Finding(
        id=row["fid"],
        title=row["title"],
        severity=row["severity"],
        category=row["category"],
        file=row["file"],
        line=row["line"],
        evidence=row["evidence"],
        description=row["description"],
        why_it_matters=row["why_it_matters"],
        recommended_fix=row["recommended_fix"],
        scanner_source=row["scanner_source"],
        confidence=row["confidence"],
    )

    result = await generate_patch(scan_id, finding, file_content)

    return {
        "patch_id": result["patch_id"],
        "provider": result["provider"],
        "explanation": result["explanation"],
        "diff": result["diff"],
        "before": result["before"][:2000],  # Truncate for display
        "after": result["after"][:2000],
        "status": "Generated using " + result["provider"],
    }


@router.post("/api/fixme/{scan_id}/verify/{patch_id}")
async def verify_finding_patch(scan_id: str, patch_id: str):
    """Apply patch to temp copy and run verification."""
    db = get_db()
    patch_row = db.execute("SELECT * FROM patches WHERE id = ?", (patch_id,)).fetchone()
    if not patch_row:
        db.close()
        raise HTTPException(status_code=404, detail="Patch not found")

    workspace = settings.workspace_path / f"workspace_{scan_id}" / "project"
    if not workspace.exists():
        db.close()
        raise HTTPException(status_code=404, detail="Original workspace not found")

    # Get all findings for rescan comparison
    findings_rows = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    db.close()

    findings = []
    for r in findings_rows:
        findings.append(Finding(
            id=r["fid"], title=r["title"], severity=r["severity"], category=r["category"],
            file=r["file"], line=r["line"], evidence=r["evidence"], description=r["description"],
            why_it_matters=r["why_it_matters"], recommended_fix=r["recommended_fix"],
            scanner_source=r["scanner_source"], confidence=r["confidence"],
        ))

    # Apply to temp copy
    try:
        patched_workspace = apply_patch_to_temp(scan_id, patch_id, workspace)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply patch: {str(e)}")

    # Verify
    verification = await verify_patch(scan_id, patch_id, patched_workspace, findings)

    return {
        "patch_id": patch_id,
        "verification": verification,
        "patched_workspace": str(patched_workspace),
        "status": "verified",
    }


@router.post("/api/fixme/{scan_id}/approve/{patch_id}")
async def approve_patch(scan_id: str, patch_id: str, approved: bool = True):
    """Approve or reject a patch."""
    db = get_db()
    if approved:
        db.execute("UPDATE patches SET status = 'approved' WHERE id = ?", (patch_id,))
    else:
        db.execute("UPDATE patches SET status = 'rejected' WHERE id = ?", (patch_id,))
    db.commit()
    db.close()

    return {
        "patch_id": patch_id,
        "status": "approved" if approved else "rejected",
        "message": f"Patch {'approved' if approved else 'rejected'}. Original project is never modified.",
    }


@router.post("/api/fixme/{scan_id}/rollback/{patch_id}")
async def rollback_patch(scan_id: str, patch_id: str):
    """Rollback a patch - remove the temp copy."""
    import shutil
    db = get_db()
    db.execute("UPDATE patches SET status = 'rolled_back' WHERE id = ?", (patch_id,))
    db.commit()
    db.close()

    # Remove the patched workspace
    patched_dir = settings.workspace_path / f"patched_{scan_id}_{patch_id[:8]}"
    if patched_dir.exists():
        shutil.rmtree(patched_dir)

    return {"patch_id": patch_id, "status": "rolled_back", "message": "Patch rolled back. Temp copy removed."}


@router.get("/api/fixme/{scan_id}/patches")
async def list_patches(scan_id: str):
    """Get patch history for a scan."""
    return {"patches": get_patch_history(scan_id)}


@router.get("/api/fixme/{scan_id}/before-after")
async def get_before_after(scan_id: str):
    """Get before/after comparison."""
    from ..scoring import calculate_score, get_before_after_comparison
    db = get_db()
    findings_rows = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    patches = db.execute("SELECT * FROM patches WHERE scan_id = ? AND status IN ('approved', 'verified', 'applied')", (scan_id,)).fetchall()
    db.close()

    findings = []
    for r in findings_rows:
        findings.append(Finding(
            id=r["fid"], title=r["title"], severity=r["severity"], category=r["category"],
            file=r["file"], line=r["line"], evidence=r["evidence"], description=r["description"],
            why_it_matters=r["why_it_matters"], recommended_fix=r["recommended_fix"],
            scanner_source=r["scanner_source"], confidence=r["confidence"],
        ))

    patched_ids = [p["finding_id"] for p in patches]
    comparison = get_before_after_comparison(findings, patched_ids)

    return comparison
