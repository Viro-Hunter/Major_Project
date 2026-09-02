from datetime import datetime
from typing import List, Dict

_audit: List[Dict] = []

def log_action(action_type: str, verdict: dict, executed_by: str = "system", status: str = "success", details: dict = None):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action_type": action_type,
        "verdict": verdict,
        "executed_by": executed_by,
        "status": status,
        "details": details or {}
    }
    _audit.append(entry)
    return entry

def get_logs(limit: int = 50):
    return _audit[-limit:]

def clear():
    _audit.clear()
