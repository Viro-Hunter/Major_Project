import json
import logging
import re
import os
from typing import Dict

from .groundedness_checker import indexed_edge_ids
from .risk_model import score_risk

log = logging.getLogger(__name__)

# Callers may attach analysis context to the subgraph dict under this key:
#   {"focus": <entity id>, "prevalence": {technique_node: fraction_of_users}}
# It is never sent to the LLM and does not change the subgraph's edges/ids.
CONTEXT_KEY = "_context"


def _context(subgraph: Dict) -> Dict:
    ctx = subgraph.get(CONTEXT_KEY) if isinstance(subgraph, dict) else None
    return ctx if isinstance(ctx, dict) else {}


def _behavioral_template(subgraph: Dict, query: str, focus: str, prevalence) -> Dict | None:
    """Template verdict driven by ATT&CK evidence paths (Week 9). None if there is no technique evidence."""
    from .evidence import behavioral_risk

    analysis = behavioral_risk(subgraph, focus, prevalence)
    if not analysis["techniques"]:
        return None
    risk = analysis["risk"]
    level = "HIGH" if risk >= 0.7 else "MEDIUM" if risk >= 0.4 else "LOW"
    parts = []
    cited: list[str] = []
    for c in analysis["techniques"][:5]:
        parts.append(
            f"{c['technique_id']} via {c['pattern'] or 'technique match'} "
            f"({c['support']} supporting event{'s' if c['support'] != 1 else ''}, "
            f"path confidence {c['path_confidence']:.2f}, seen in {c['peer_prevalence']:.0%} of peers)"
        )
        for eid in c.get("supporting_edge_ids") or c["edge_ids"]:
            if eid not in cited:
                cited.append(eid)
    narrative = (
        f"{focus}: {len(analysis['techniques'])} distinct ATT&CK technique(s) linked by evidence paths — "
        + "; ".join(parts)
        + f". Combined behavioural risk {risk:.2f} ({level}). "
        + ("Multiple distinct stages co-occur — recommend analyst review." if len(analysis["techniques"]) >= 2 and risk >= 0.4
           else "Behaviour is common among peers or weakly supported." if risk < 0.4 else "Review recommended.")
    )
    return {
        "narrative": narrative,
        "risk_score": round(risk, 3),
        "confidence": round(analysis["propagated_confidence"], 3),
        "evidence_edges": len(cited),
        "cited_edges": cited,
        "grounded": True,
        "model": "template-fallback",
        "techniques": analysis["techniques"],
    }


def _template_verdict(subgraph: Dict, query: str) -> Dict:
    """Fallback when the LLM is offline — deterministic, grounded."""
    ctx = _context(subgraph)
    if ctx.get("focus"):
        behavioural = _behavioral_template(subgraph, query, ctx["focus"], ctx.get("prevalence"))
        if behavioural is not None:
            return behavioural
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


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def extract_json_object(text: str) -> dict | None:
    """First JSON object in an LLM reply, tolerating what real models wrap around it:
    <think>...</think> reasoning blocks, markdown fences, a preamble ("Here is the analysis:")
    and trailing commentary. Prefers an object that contains a "narrative" key."""
    if not text:
        return None
    text = _THINK_RE.sub("", text)
    text = re.sub(r"```(?:json)?", "", text)
    decoder = json.JSONDecoder()
    found = []
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[i:])
        except ValueError:
            continue
        if isinstance(obj, dict):
            if "narrative" in obj or "explanation" in obj or "answer" in obj:
                return obj
            found.append(obj)
    return found[0] if found else None


def _ollama_verdict(subgraph: Dict, query: str, extra_instruction: str | None = None) -> Dict | None:
    """Back-compat wrapper: the verdict, or None (reason available via _llm_verdict)."""
    return _llm_verdict(subgraph, query, extra_instruction)[0]


def _llm_verdict(subgraph: Dict, query: str, extra_instruction: str | None = None) -> tuple[Dict | None, str | None]:
    """Try Ollama via llm/client.py — returns None if offline.

    Set ``CYBERGRAPHRAG_OFFLINE=1`` to skip the .env/Ollama LLM (CI, benchmarks
    without a model) instead of paying the client's connection-retry backoff.
    """
    from llm.runtime import get_active

    # A key connected from the dashboard is an explicit opt-in and overrides offline mode.
    if get_active() is None and os.getenv("CYBERGRAPHRAG_OFFLINE", "").strip().lower() in ("1", "true", "yes"):
        return None, "offline"
    model_name = None
    try:
        from llm.client import LLMClient

        # Use OpenAI-compatible Ollama (default llm/client handles OPENAI_API_BASE)
        client = LLMClient()  # dashboard connection > .env > local Ollama
        model_name = client.model
        system_prompt = (
            "You are an insider-threat analyst writing for a non-specialist reader. "
            "Given a subgraph of one employee's log records (edges with ids, some linked to MITRE ATT&CK behaviours) and "
            "a question, produce JSON with keys: narrative, risk_score (0-1, your own estimate), confidence (0-1), "
            "evidence_edges (int), cited_edges (list of the exact edge 'id' strings that support your narrative). "
            "Write the narrative in plain English, 3-5 sentences: say what the person did and when, why it is unusual, "
            "and what an analyst should check. Do NOT put edge ids, technique codes (T1005...) or relation names "
            "(OBSERVED_ON...) in the narrative; put ids only in cited_edges. "
            "Ground every claim in a real edge and cite ONLY ids that appear in the subgraph. Never speculate about "
            "the person's character or personal life."
        )
        # Every edge gets a stable id (its own, or positional e<index>) so the model can cite it
        # and reasoning.groundedness_checker can verify it.
        all_ids = indexed_edge_ids(subgraph)
        edges = subgraph.get("edges", [])
        # Keep subgraph compact for a local small-model context window, but put the
        # ATT&CK evidence-path edges FIRST so they are never truncated away.
        ctx = _context(subgraph)
        analysis = None
        priority: list[int] = []
        evidence_summary = ""
        if ctx.get("focus"):
            from .evidence import behavioral_risk

            analysis = behavioral_risk(subgraph, ctx["focus"], ctx.get("prevalence"))
            pos = {eid: i for i, eid in enumerate(all_ids)}
            for c in analysis["techniques"]:
                priority.extend(pos[e] for e in c["edge_ids"] if e in pos and pos[e] not in priority)
            if analysis["techniques"]:
                evidence_summary = "Evidence paths (technique, pattern, path confidence, peer prevalence, edge ids): " + json.dumps(
                    [[c["technique_id"], c["pattern"], c["path_confidence"], c["peer_prevalence"], c["edge_ids"]] for c in analysis["techniques"][:8]]
                ) + "\n"
        order = priority + [i for i in range(len(edges)) if i not in set(priority)]
        keep = order[:40]
        node_ids = {edges[i].get("source") for i in keep} | {edges[i].get("target") for i in keep}
        nodes = [n for n in subgraph.get("nodes", []) if n.get("id") in node_ids][:40]
        compact = {
            "nodes": [{k: v for k, v in n.items() if k in ("id", "type", "name")} for n in nodes],
            "edges": [
                {"id": all_ids[i], **{k: v for k, v in edges[i].items() if k in ("source", "target", "type", "relation", "confidence", "timestamp", "pattern")}}
                for i in keep
            ],
        }
        user_prompt = f"Subgraph: {json.dumps(compact, default=str)}\n{evidence_summary}Question: {query}\nRespond JSON only."
        if extra_instruction:
            user_prompt += "\n\n" + extra_instruction
        resp = client.call(system_prompt, user_prompt)
        model_name = getattr(resp, "model", None) or model_name  # routers: the model that actually answered
        text = (resp.content or "").strip()
        if not text:
            return None, f"{model_name} returned an empty reply (reasoning models can use up their whole token budget thinking)"
        data = extract_json_object(text)
        if data is None:
            return None, f"{model_name} did not reply in the required JSON format"
        narrative = data.get("narrative") or data.get("explanation") or data.get("answer") or ""
        if not narrative or len(narrative.strip()) < 10:
            return None, f"{model_name} returned no explanation"
        cited = [str(c) for c in (data.get("cited_edges") or [])]
        if not cited and subgraph.get("edges"):
            # Evidence exists but the model cited none: unverifiable, so use the grounded template.
            return None, f"{model_name} cited no evidence, so its answer could not be checked"
        risk = float(data.get("risk_score", score_risk(subgraph)))
        conf = float(data.get("confidence", 0.8))
        ev = int(data.get("evidence_edges", len(subgraph.get("edges", []))))
        # Clamp risk: if model says 0 but edges exist, use calibrated risk
        if risk == 0 and len(subgraph.get("edges", [])) > 0:
            risk = score_risk(subgraph)
        model_risk = round(max(0.0, min(1.0, risk)), 3)
        # The decision-driving risk comes from the evidence (deterministic, auditable, the same whichever
        # model answers). The model's own number is kept for transparency as model_risk.
        if analysis is not None and analysis["techniques"]:
            risk = analysis["risk"]
        return {
            "narrative": narrative,
            "risk_score": round(max(0.0, min(1.0, risk)), 3),
            "model_risk": model_risk,
            "confidence": round(max(0.0, min(1.0, conf)), 3),
            "evidence_edges": ev,
            "cited_edges": cited,
            "grounded": True,  # provisional; reasoning.groundedness_checker.check_groundedness sets the real value
            "model": model_name,
        }, None
    except Exception as e:  # network, timeout, rate limit, auth...
        log.warning("LLM verdict failed (%s): %s", model_name, e)
        return None, describe_llm_error(e, model_name)


def describe_llm_error(e: Exception, model: str | None) -> str:
    """A short, honest reason a person can act on."""
    msg, name = str(e), e.__class__.__name__
    who = model or "The AI model"
    if "429" in msg or "RateLimit" in name:
        return f"{who} is rate-limited (free models allow only a few requests per minute); try again shortly or pick another model"
    if "402" in msg:
        return f"{who} needs credit on your OpenRouter account"
    if "Timeout" in name or "timed out" in msg.lower():
        return f"{who} took too long to answer; a smaller or faster model may help"
    if "401" in msg or "403" in msg or "Authentication" in name:
        return f"{who} rejected the API key"
    if "Connection" in name or "connect" in msg.lower():
        return "no AI model could be reached (is Ollama running, or is a key connected?)"
    return f"{who} failed ({name})"


def generate_verdict(subgraph: Dict, query: str, extra_instruction: str | None = None) -> Dict:
    """Primary: Ollama via llm/client.py — NOT hardcoded.

    Returns the raw verdict. Groundedness is NOT enforced here: the caller
    (api/routes/incidents.py) must pass the result through
    reasoning.groundedness_checker.check_groundedness, which verifies cited
    edges, retries via ``extra_instruction`` and downgrades if still ungrounded.
    """
    result, reason = _llm_verdict(subgraph, query, extra_instruction)
    if result is not None:
        return result
    # Offline / malformed / uncited output -> deterministic template (grounded by construction),
    # labelled with WHY the model's answer was not used so the UI can say so honestly.
    verdict = _template_verdict(subgraph, query)
    verdict["fallback_reason"] = reason
    return verdict
