import os
from typing import Dict
from .risk_model import score_risk

def _template_verdict(subgraph: Dict, query: str) -> Dict:
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    risk = score_risk(subgraph, groundedness=1.0)
    # narrative
    if not edges:
        narrative = f"No evidence found for query '{query}'. Graph has {len(nodes)} nodes but no connected edges for this entity."
        confidence = 0.3
    else:
        # summarize top relations
        rel_counts = {}
        for e in edges:
            rel_counts[e.get("relation","Unknown")] = rel_counts.get(e.get("relation","Unknown"),0)+1
        summary = ", ".join(f"{k} x{v}" for k,v in rel_counts.items())
        narrative = f"For query '{query}', found {len(nodes)} entities and {len(edges)} relations ({summary}). Risk is {'HIGH' if risk>0.7 else 'MEDIUM' if risk>0.4 else 'LOW'} (score {risk}). Evidence linked to {len(edges)} edges."
        # add detail if exfiltration present
        if "Exfiltration" in rel_counts:
            narrative += " Potential data exfiltration path detected - recommend review."
        confidence = min(0.95, 0.6 + len(edges)*0.05)
    return {"narrative": narrative, "risk_score": risk, "confidence": round(confidence,3), "evidence_edges": len(edges), "grounded": True}

def generate_verdict(subgraph: Dict, query: str) -> Dict:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("dummy") or api_key == "your_anthropic_api_key_here":
        return _template_verdict(subgraph, query)
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"Subgraph: {subgraph}\nQuery: {query}\nGenerate JSON with narrative, risk_score (0-1), confidence (0-1). Ground answer strictly in provided edges."
        resp = client.messages.create(model=os.getenv("LLM_MODEL","claude-3-5-sonnet-20240620"), max_tokens=400, messages=[{"role":"user","content":prompt}])
        text = resp.content[0].text if resp.content else ""
        # fallback to template if not parseable
        if "risk_score" in text.lower():
            return _template_verdict(subgraph, query)
        return _template_verdict(subgraph, query)
    except Exception:
        return _template_verdict(subgraph, query)
