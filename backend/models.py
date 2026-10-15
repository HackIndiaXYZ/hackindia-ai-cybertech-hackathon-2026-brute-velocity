"""
Velbrix - Pydantic models
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class Finding(BaseModel):
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    file: str
    line: int = 0
    evidence: str = ""
    description: str = ""
    why_it_matters: str = ""
    recommended_fix: str = ""
    scanner_source: str = "custom"
    confidence: float = 0.8


class ScanResult(BaseModel):
    scan_id: str
    project_name: str
    status: str
    stack: str = "Unknown"
    file_count: int = 0
    findings: List[Finding] = []
    overall_score: int = 0
    decision: str = "REVIEW"
    category_scores: Dict[str, int] = {}
    summary: str = ""


class PatchRequest(BaseModel):
    scan_id: str
    finding_id: str


class PatchApproval(BaseModel):
    patch_id: str
    approved: bool


class AgentActionTest(BaseModel):
    scan_id: str
    action_type: str  # read_source, read_env, send_external, install_package, shell_command


class SessionTestRequest(BaseModel):
    scan_id: str
