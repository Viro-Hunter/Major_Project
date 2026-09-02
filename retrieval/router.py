"""Routing policy for incident questions — hybrid.

Keeps remote RuleBasedQueryClassifier for test compatibility plus advanced hybrid logic.
"""
from __future__ import annotations

from typing import Protocol

STRUCTURAL_KEYWORDS = ("why", "linked to", "path", "connected")
LOOKUP_KEYWORDS = ("what is", "when did")


class QueryClassifier(Protocol):
    def classify(self, question: str) -> str: ...


class RuleBasedQueryClassifier:
    def classify(self, question: str) -> str:
        normalized = " ".join(question.lower().split())
        if any(keyword in normalized for keyword in STRUCTURAL_KEYWORDS):
            return "structural"
        return "lookup"


_classifier: QueryClassifier = RuleBasedQueryClassifier()


def classify_query(question: str) -> str:
    """Return ``structural`` for multi-hop questions, otherwise ``lookup``.

    Hybrid logic preserved for advanced pipeline: if question contains both structural
    and lookup keywords, returns ``hybrid``.
    """
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must be a non-empty string")
    # First, use remote logic for test compatibility
    remote = _classifier.classify(question)
    # Advanced extension: detect hybrid
    q = question.lower()
    # advanced keywords
    structural_kw = ["who", "what did", "connected", "relations", "graph", "path", "exfiltr", "accessed", "host", "user"]
    lookup_kw = ["mean", "explain", "definition", "semantic", "similar", "behavior"]
    # If remote says structural, keep it (covers why/linked to/path/connected)
    # Only upgrade to hybrid if both types present
    s = sum(1 for k in structural_kw if k in q)
    l = sum(1 for k in lookup_kw if k in q)
    if s > 0 and l > 0:
        return "hybrid"
    # For remote test cases, ensure lookup vs structural matches remote exactly
    # Remote already decides; keep it
    return remote
