from typing import Dict

def score_risk(subgraph: Dict, groundedness: float = 1.0) -> float:
    edges = subgraph.get("edges", [])
    if not edges:
        return 0.1
    # avg confidence weighted by relation severity
    severity = {"Exfiltration":1.0, "PrivEsc":0.95, "FailedLogin":0.6, "Copied":0.85, "Accessed":0.4, "ConnectedTo":0.3}
    total = 0
    w = 0
    for e in edges:
        rel = e.get("relation","")
        conf = float(e.get("confidence",0.7))
        sev = severity.get(rel, 0.5)
        total += conf * sev
        w += sev if sev else 1
    avg = total / max(w,1) if w else 0.5
    # boost if multiple high-risk edges
    high = sum(1 for e in edges if e.get("relation") in ("Exfiltration","PrivEsc"))
    boost = min(0.2, high*0.08)
    risk = min(0.99, avg + boost) * groundedness
    # calibrate to 0-1
    return round(float(risk), 3)
