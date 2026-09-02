"""Routing policy for incident questions.

The public ``classify_query`` function is intentionally stable; the strategy
object can later be replaced with a trained classifier without changing callers.
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
    """Return ``structural`` for multi-hop questions, otherwise ``lookup``."""
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must be a non-empty string")
    return _classifier.classify(question)
