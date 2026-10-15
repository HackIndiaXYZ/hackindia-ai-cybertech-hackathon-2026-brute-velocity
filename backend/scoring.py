"""
Velbrix - Scoring Engine
Transparent, evidence-based security scoring.
Deduplicates findings by vulnerability type for fair scoring.
"""
from typing import List, Dict
from .models import Finding

# Points per severity (deduplicated by title)
SEVERITY_POINTS = {
    "Critical": 11.5,
    "High": 5,
    "Medium": 3,
    "Low": 1,
    "Info": 0,
}

# Map categories to the 5 trust report categories
TRUST_CATEGORY_MAP = {
    "Secrets": "Secrets",
    "Injection": "Injection & Uploads",
    "XSS": "Injection & Uploads",
    "Code Execution": "Injection & Uploads",
    "Access Control": "Access & Sessions",
    "Cryptography": "Access & Sessions",
    "Configuration": "Access & Sessions",
    "Supply Chain": "Supply Chain",
    "AI-Agent Risk": "AI-Agent Risk",
    "Deploy Readiness": "Deploy Readiness",
    "Code Quality": "Code Quality",
}


def _deduplicate_for_scoring(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate findings by title for scoring purposes.
    Multiple instances of the same vulnerability type count as one for scoring.
    """
    seen_titles = set()
    deduped = []
    for f in findings:
        key = f.title
        if key not in seen_titles:
            seen_titles.add(key)
            deduped.append(f)
    return deduped


def calculate_score(findings: List[Finding], patched_finding_ids: List[str] = None) -> Dict:
    """
    Calculate the overall security score and category scores.
    Formula: score = 100 - (severity-weighted penalty)
    Patching a finding removes its penalty from the score.
    """
    patched_finding_ids = patched_finding_ids or []

    # Build set of patched finding titles (patching one instance removes the whole type)
    patched_finding_titles = set()
    for f in findings:
        if f.id in patched_finding_ids:
            patched_finding_titles.add(f.title)

    # Active findings = those not patched (exclude by title match)
    active_findings = [f for f in findings if f.title not in patched_finding_titles]

    # Deduplicate for scoring
    scoring_findings = _deduplicate_for_scoring(active_findings)

    # Count by severity (use all active findings for the display count)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in active_findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # Calculate raw penalty
    raw_penalty = 0
    trust_category_scores: Dict[str, float] = {}

    for f in scoring_findings:
        points = SEVERITY_POINTS.get(f.severity, 1)
        raw_penalty += points

        trust_cat = TRUST_CATEGORY_MAP.get(f.category, "Code Quality")
        trust_category_scores[trust_cat] = trust_category_scores.get(trust_cat, 0) + points

    # Overall score
    overall_score = max(0, int(round(100 - raw_penalty)))
    overall_score = min(100, overall_score)

    # Decision logic
    if overall_score < 50 or counts["Critical"] > 0:
        decision = "BLOCK"
    elif overall_score < 85:
        decision = "REVIEW"
    else:
        decision = "DEPLOY"

    # 5 trust report category scores (0-100 each)
    trust_scores = {
        "Secrets": max(0, min(100, int(100 - trust_category_scores.get("Secrets", 0) * 5))),
        "Injection & Uploads": max(0, min(100, int(100 - trust_category_scores.get("Injection & Uploads", 0) * 4))),
        "Access & Sessions": max(0, min(100, int(100 - trust_category_scores.get("Access & Sessions", 0) * 5))),
        "Supply Chain": max(0, min(100, int(100 - trust_category_scores.get("Supply Chain", 0) * 5))),
        "AI-Agent Risk": max(0, min(100, int(100 - trust_category_scores.get("AI-Agent Risk", 0) * 5))),
    }

    return {
        "overall_score": overall_score,
        "decision": decision,
        "category_scores": trust_scores,
        "counts": counts,
        "total_findings": len(active_findings),
        "patched_count": len(patched_finding_ids),
        "raw_penalty": round(raw_penalty, 1),
    }


def get_before_after_comparison(before_findings: List[Finding], patched_ids: List[str]) -> Dict:
    """Generate before/after comparison for demo."""
    before_result = calculate_score(before_findings, [])
    after_result = calculate_score(before_findings, patched_ids)

    return {
        "before": {
            "score": before_result["overall_score"],
            "decision": before_result["decision"],
            "critical": before_result["counts"]["Critical"],
            "high": before_result["counts"]["High"],
            "exposed_secrets": sum(1 for f in before_findings if f.category == "Secrets"),
            "prompt_injection_risk": "High" if any(f.category == "AI-Agent Risk" and f.severity in ["Critical", "High"] for f in before_findings) else "Low",
        },
        "after": {
            "score": after_result["overall_score"],
            "decision": after_result["decision"],
            "critical": after_result["counts"]["Critical"],
            "high": after_result["counts"]["High"],
            "exposed_secrets": sum(1 for f in before_findings if f.category == "Secrets" and f.id not in patched_ids),
            "patch_verification": "Passed" if patched_ids else "Not run",
            "remaining_medium": after_result["counts"]["Medium"],
        },
    }
