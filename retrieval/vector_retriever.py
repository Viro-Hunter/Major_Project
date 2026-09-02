from typing import List, Dict
from difflib import SequenceMatcher

# very lightweight semantic fallback: rank nodes/edges by textual similarity to query

def semantic_search(query: str, subgraph: Dict, top_k: int = 5) -> Dict:
    q = query.lower()
    def score(text: str) -> float:
        return SequenceMatcher(None, q, text.lower()).ratio()
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    # score nodes
    for n in nodes:
        n["_score"] = score(n.get("id","") + " " + n.get("type",""))
    for e in edges:
        e["_score"] = score(e.get("relation","") + " " + e.get("source","") + " " + e.get("target",""))
    nodes_sorted = sorted(nodes, key=lambda x: x["_score"], reverse=True)[:top_k]
    edges_sorted = sorted(edges, key=lambda x: x["_score"], reverse=True)[:top_k]
    return {"nodes": nodes_sorted, "edges": edges_sorted, "query": query}
