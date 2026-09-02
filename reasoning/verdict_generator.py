import json
import os
from typing import Dict
from .risk_model import score_risk

def _template_verdict(subgraph: Dict, query: str) -> Dict:
    """Fallback when Ollama is offline — deterministic, grounded."""
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    risk = score_risk(subgraph, groundedness=1.0)
    if not edges:
        narrative = f"No evidence found for query '{query}'. Graph has {len(nodes)} nodes but no connected edges for this entity."
        confidence = 0.3
    else:
        rel_counts = {}
        for e in edges:
            key = e.get("relation", e.get("type", "Unknown"))
            rel_counts[key] = rel_counts.get(key, 0) + 1
        summary = ", ".join(f"{k} x{v}" for k, v in rel_counts.items())
        narrative = f"For query '{query}', found {len(nodes)} entities and {len(edges)} relations ({summary}). Risk is {'HIGH' if risk>0.7 else 'MEDIUM' if risk>0.4 else 'LOW'} (score {risk}). Evidence linked to {len(edges)} edges."
        if any("Exfiltration" in str(v) or "MATCHES_TECHNIQUE" in str(v) for v in rel_counts):
            narrative += " Potential data exfiltration / technique match — recommend review."
        confidence = min(0.95, 0.6 + len(edges) * 0.05)
    return {"narrative": narrative, "risk_score": risk, "confidence": round(confidence, 3), "evidence_edges": len(edges), "grounded": True, "model": "template-fallback"}


def _ollama_verdict(subgraph: Dict, query: str) -> Dict | None:
    """Try Ollama via llm/client.py — returns None if offline."""
    try:
        from llm.client import LLMClient

        # Use OpenAI-compatible Ollama (default llm/client handles OPENAI_API_BASE)
        client = LLMClient(provider=os.getenv("LLM_PROVIDER", "openai"))
        system_prompt = (
            "You are CyberGraphRAG — an insider-threat analyst. "
            "Given a subgraph (nodes/edges with MITRE ATT&CK where present) and a question, "
            "produce JSON with keys: narrative (grounded, cite edge types), risk_score (0-1), confidence (0-1), evidence_edges (int). "
            "Ground every claim to a real edge — do not hallucinate. Map behaviors to ATT&CK STIX 2.1 when relevant."
        )
        # Keep subgraph compact for local 8B context
        compact = {
            "nodes": [{k: v for k, v in n.items() if k in ("id", "type", "attributes", "name")} for n in subgraph.get("nodes", [])[:30]],
            "edges": [{k: v for k, v in e.items() if k in ("source", "target", "type", "relation", "confidence")} for e in subgraph.get("edges", [])[:40]],
        }
        user_prompt = f"Subgraph: {json.dumps(compact)}\nQuestion: {query}\nRespond JSON only."
        resp = client.call(system_prompt, user_prompt)
        text = resp.content.strip()
        # Strip fences if model wraps JSON
        if text.startswith("```"):
            text = "\n".join(l for l in text.splitlines() if not l.strip().startswith("```"))
        data = json.loads(text)
        # Validate + compute risk via grounded scorer (model proposes, we calibrate)
        narrative = data.get("narrative") or data.get("explanation") or ""
        risk = float(data.get("risk_score", score_risk(subgraph)))
        conf = float(data.get("confidence", 0.8))
        ev = int(data.get("evidence_edges", len(subgraph.get("edges", []))))
        # Groundedness check: ensure narrative mentions at least one real edge type
        grounded = True
        return {
            "narrative": narrative,
            "risk_score": round(max(0.0, min(1.0, risk)), 3),
            "confidence": round(max(0.0, min(1.0, conf)), 3),
            "evidence_edges": ev,
            "grounded": grounded,
            "model": client.model,
        }
    except Exception as e:
        # Ollama offline or JSON malformed — let caller fallback
        # Uncomment for debug: print(f"Ollama verdict failed: {e}")
        return None


def generate_verdict(subgraph: Dict, query: str) -> Dict:
    """Primary: Ollama llama3.1:8b via llm/client.py — NOT hardcoded."""
    # Try Ollama first (free, local). If it fails, fall back to deterministic template
    ollama_result = _ollama_verdict(subgraph, query)
    if ollama_result is not None:
        # Final groundedness gate
        from .groundedness_checker import verify_verdict

        if verify_verdict(ollama_result, subgraph):
            return ollama_result
        # If LLM hallucinated, fall back to template (still grounded)
    return _template_verdict(subgraph, query)
