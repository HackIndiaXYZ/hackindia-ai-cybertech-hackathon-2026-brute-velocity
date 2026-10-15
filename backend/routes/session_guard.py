"""
Velbrix - SessionGuard Route
"""
from fastapi import APIRouter
from ..session_guard import run_session_audit, get_session_results

router = APIRouter()


@router.post("/api/sessionguard/{scan_id}/run")
async def run_session_audit_route(scan_id: str):
    """Run the SessionGuard audit using synthetic tokens."""
    results = run_session_audit(scan_id)
    passed = sum(1 for r in results if r["result"] == "PASS")
    failed = sum(1 for r in results if r["result"] == "FAIL")

    return {
        "scan_id": scan_id,
        "total_checks": len(results),
        "passed": passed,
        "failed": failed,
        "results": results,
        "note": "Tested against authorized local test app with synthetic tokens. No real credentials used.",
    }


@router.get("/api/sessionguard/{scan_id}/results")
async def get_session_results_route(scan_id: str):
    """Get stored session test results."""
    results = get_session_results(scan_id)
    return {
        "scan_id": scan_id,
        "results": results,
        "total": len(results),
    }
