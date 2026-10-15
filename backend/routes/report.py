"""
Velbrix - Trust Report Route
"""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse
from ..database import get_db
from ..models import Finding
from ..report_generator import generate_report
from ..config import settings

router = APIRouter()


@router.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Generate and return the trust report."""
    db = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        db.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_rows = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    patches = [dict(r) for r in db.execute("SELECT * FROM patches WHERE scan_id = ?", (scan_id,)).fetchall()]
    agent_actions = [dict(r) for r in db.execute("SELECT * FROM agent_actions WHERE scan_id = ?", (scan_id,)).fetchall()]
    session_rows = db.execute("SELECT * FROM session_tests WHERE scan_id = ?", (scan_id,)).fetchall()
    db.close()

    findings = []
    for r in findings_rows:
        findings.append(Finding(
            id=r["fid"], title=r["title"], severity=r["severity"], category=r["category"],
            file=r["file"], line=r["line"], evidence=r["evidence"], description=r["description"],
            why_it_matters=r["why_it_matters"], recommended_fix=r["recommended_fix"],
            scanner_source=r["scanner_source"], confidence=r["confidence"],
        ))

    patched_ids = [p["finding_id"] for p in patches if p["status"] in ["approved", "verified", "applied"]]

    session_results = []
    for r in session_rows:
        try:
            session_results.append(json.loads(r["evidence"]))
        except Exception:
            session_results.append({"check_name": r["check_name"], "result": r["result"], "evidence": "N/A"})

    report = generate_report(scan_id, scan["project_name"], findings, patched_ids, patches, agent_actions, session_results)

    # Save report to file
    report_dir = settings.workspace_path / f"workspace_{scan_id}" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "trust_report.html").write_text(report["html"], encoding="utf-8")
    (report_dir / "trust_report.md").write_text(report["markdown"], encoding="utf-8")

    # Parse key values for JSON response
    from ..scoring import calculate_score
    score_result = calculate_score(findings, patched_ids)

    return {
        "scan_id": scan_id,
        "project_name": scan["project_name"],
        "overall_score": score_result["overall_score"],
        "decision": score_result["decision"],
        "category_scores": score_result["category_scores"],
        "counts": score_result["counts"],
        "total_findings": len(findings),
        "patched_count": len(patched_ids),
        "patches": [{"id": p["id"][:8], "status": p["status"], "finding_id": p["finding_id"]} for p in patches],
        "agent_actions_count": len(agent_actions),
        "session_checks_count": len(session_results),
        "html_report_url": f"/api/report/{scan_id}/html",
        "markdown_report_url": f"/api/report/{scan_id}/markdown",
        "note": "Automated assessment, not a guarantee.",
    }


@router.get("/api/report/{scan_id}/html")
async def get_html_report(scan_id: str):
    """Get the HTML report."""
    report_file = settings.workspace_path / f"workspace_{scan_id}" / "reports" / "trust_report.html"
    if not report_file.exists():
        # Generate it
        await get_report(scan_id)
    content = report_file.read_text(encoding="utf-8")
    return HTMLResponse(content=content)


@router.get("/api/report/{scan_id}/markdown")
async def get_markdown_report(scan_id: str):
    """Get the Markdown report."""
    report_file = settings.workspace_path / f"workspace_{scan_id}" / "reports" / "trust_report.md"
    if not report_file.exists():
        await get_report(scan_id)
    content = report_file.read_text(encoding="utf-8")
    return PlainTextResponse(content=content, media_type="text/markdown")
