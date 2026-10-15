"""
Velbrix - AgentGuard Route
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..agent_guard import evaluate_action, get_action_log, get_demo_scenarios, AGENT_POLICIES

router = APIRouter()


class ActionRequest(BaseModel):
    action_type: str
    custom_evidence: Optional[str] = ""


@router.get("/api/agentguard/{scan_id}/scenarios")
async def get_scenarios(scan_id: str):
    """Get demo scenarios for the UI."""
    return {"scenarios": get_demo_scenarios(), "policies": [{"name": k, **v} for k, v in AGENT_POLICIES.items()]}


@router.post("/api/agentguard/{scan_id}/test")
async def test_action(scan_id: str, req: ActionRequest):
    """Test an AI agent action against the policy."""
    result = evaluate_action(scan_id, req.action_type, req.custom_evidence)
    return result


@router.get("/api/agentguard/{scan_id}/log")
async def get_log(scan_id: str):
    """Get the action log."""
    return {"actions": get_action_log(scan_id)}


@router.get("/api/agentguard/{scan_id}/policies")
async def get_policies(scan_id: str):
    """Get all AgentGuard policies."""
    return {"policies": [{"name": k, **v} for k, v in AGENT_POLICIES.items()]}
