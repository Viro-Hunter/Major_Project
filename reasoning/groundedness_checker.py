from typing import Dict

def verify_verdict(verdict: Dict, subgraph: Dict) -> bool:
    # simple check: verdict evidence_edges should <= actual edges, narrative should not claim unknown relations
    edges = subgraph.get("edges", [])
    claimed = verdict.get("evidence_edges", 0)
    if claimed > len(edges):
        return False
    # if verdict says rooted but no edges, fail
    narrative = verdict.get("narrative","").lower()
    if "exfiltration" in narrative:
        has = any(e.get("relation")=="Exfiltration" for e in edges)
        if not has:
            return False
    return True

def maybe_regenerate(verdict: Dict, subgraph: Dict, query: str):
    if verify_verdict(verdict, subgraph):
        return verdict
    # regenerate with stricter template
    from .verdict_generator import generate_verdict
    # force template path
    import os
    old = os.getenv("LLM_API_KEY")
    os.environ["LLM_API_KEY"] = "dummy-for-testing"
    v2 = generate_verdict(subgraph, query)
    if old is not None:
        os.environ["LLM_API_KEY"] = old
    else:
        os.environ.pop("LLM_API_KEY", None)
    return v2
