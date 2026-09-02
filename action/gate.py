import os

def should_auto_execute(risk_score: float, auto_threshold: float = None, analyst_threshold: float = None) -> str:
    # returns "auto", "analyst", "ignore"
    auto = auto_threshold if auto_threshold is not None else float(os.getenv("ACTION_AUTO_THRESHOLD","0.85"))
    analyst = analyst_threshold if analyst_threshold is not None else float(os.getenv("ACTION_ANALYST_THRESHOLD","0.50"))
    if risk_score >= auto:
        return "auto"
    if risk_score >= analyst:
        return "analyst"
    return "ignore"
