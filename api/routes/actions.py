from fastapi import APIRouter
from pydantic import BaseModel
from action.audit_log import get_logs, log_action
from action.simulated_actions import block_ip, force_reauth_user, quarantine_host

router = APIRouter(prefix="/actions", tags=["actions"])

class ActionReq(BaseModel):
    target: str
    type: str  # block_ip, force_reauth, quarantine

@router.post("")
async def do_action(req: ActionReq):
    if req.type == "block_ip":
        result = block_ip(req.target)
    elif req.type == "force_reauth":
        result = force_reauth_user(req.target)
    elif req.type == "quarantine":
        result = quarantine_host(req.target)
    else:
        result = {"action": req.type, "target": req.target, "status": "unknown_action"}
    log_action(req.type, {"risk_score": 0.0}, executed_by="analyst", status="executed", details=result)
    return result

@router.get("")
async def list_actions(limit: int = 20):
    return {"logs": get_logs(limit)}

@router.post("/{action_id}/approve")
async def approve(action_id: str):
    # stub: just log approval
    log_action("approve", {"risk_score": 0.0}, executed_by="analyst", status="approved", details={"action_id": action_id})
    return {"action_id": action_id, "status": "approved"}
