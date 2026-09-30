import json
import os
from typing import Dict

from .groundedness_checker import indexed_edge_ids
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
    return {
        "narrative": narrative,
        "risk_score": risk,
        "confidence": round(confidence, 3),
        "evidence_edges": len(edges),
        # The template summarises every edge in the subgraph, so all are cited (grounded by construction).
        "cited_edges": indexed_edge_ids(subgraph),
        "grounded": True,
        "model": "template-fallback",
    }


def _ollama_verdict(subgraph: Dict, query: str, extra_instruction: str | None = None) -> Dict | None:
    """Try Ollama via llm/client.py — returns None if offline."""
    try:
        from llm.client import LLMClient

        # Use OpenAI-compatible Ollama (default llm/client handles OPENAI_API_BASE)
        client = LLMClient(provider=os.getenv("LLM_PROVIDER", "openai"))
        system_prompt = (
            "You are CyberGraphRAG — an insider-threat analyst. "
            "Given a subgraph (nodes/edges with MITRE ATT&CK where present) and a question, "
            "produce JSON with keys: narrative (grounded, cite edge types), risk_score (0-1), confidence (0-1), "
            "evidence_edges (int), cited_edges (list of the exact edge 'id' strings that support your narrative). "
            "Ground every claim to a real edge and cite ONLY ids that appear in the subgraph — do not hallucinate. "
            "Map behaviors to ATT&CK STIX 2.1 when relevant."
        )
        # Every edge gets a stable id (its own, or positional e<index>) so the model can cite it
        # and reasoning.groundedness_checker can verify it.
        all_ids = indexed_edge_ids(subgraph)
        # Keep subgraph compact for local 8B context
        compact = {
            "nodes": [{k: v for k, v in n.items() if k in ("id", "type", "attributes", "name")} for n in subgraph.get("nodes", [])[:30]],
            "edges": [
                {"id": all_ids[i], **{k: v for k, v in e.items() if k in ("source", "target", "type", "relation", "confidence")}}
                for i, e in enumerate(subgraph.get("edges", [])[:40])
            ],
        }
        user_prompt = f"Subgraph: {json.dumps(compact)}\nQuestion: {query}\nRespond JSON only."
        if extra_instruction:
            user_prompt += "\n\n" + extra_instruction
        resp = client.call(system_prompt, user_prompt)
        text = resp.content.strip()
        # Strip fences if model wraps JSON
        if text.startswith("```"):
            text = "\n".join(l for l in text.splitlines() if not l.strip().startswith("```"))
        data = json.loads(text)
        # Validate
        narrative = data.get("narrative") or data.get("explanation") or ""
        if not narrative or len(narrative.strip()) < 10:
            # Small models sometimes return empty — treat as failure to trigger fallback
            return None
        cited = [str(c) for c in (data.get("cited_edges") or [])]
        if not cited and subgraph.get("edges"):
            # Evidence exists but the model cited none: unverifiable, so use the grounded template.
            return None
        risk = float(data.get("risk_score", score_risk(subgraph)))
        conf = float(data.get("confidence", 0.8))
        ev = int(data.get("evidence_edges", len(subgraph.get("edges", []))))
        # Clamp risk: if model says 0 but edges exist, use calibrated risk
        if risk == 0 and len(subgraph.get("edges", [])) > 0:
            risk = score_risk(subgraph)
        return {
            "narrative": narrative,
            "risk_score": round(max(0.0, min(1.0, risk)), 3),
            "confidence": round(max(0.0, min(1.0, conf)), 3),
            "evidence_edges": ev,
            "cited_edges": cited,
            "grounded": True,  # provisional; reasoning.groundedness_checker.check_groundedness sets the real value
            "model": client.model,
        }
    except Exception as e:
        # Ollama offline or JSON malformed — let caller fallback
        # Uncomment for debug: print(f"Ollama verdict failed: {e}")
        return None


def generate_verdict(subgraph: Dict, query: str, extra_instruction: str | None = None) -> Dict:
    """Primary: Ollama via llm/client.py — NOT hardcoded.

    Returns the raw verdict. Groundedness is NOT enforced here: the caller
    (api/routes/incidents.py) must pass the result through
    reasoning.groundedness_checker.check_groundedness, which verifies cited
    edges, retries via ``extra_instruction`` and downgrades if still ungrounded.
    """
    ollama_result = _ollama_verdict(subgraph, query, extra_instruction)
    if ollama_result is not None:
        return ollama_result
    # Ollama offline / malformed / uncited output -> deterministic template (grounded by construction)
    return _template_verdict(subgraph, query)
