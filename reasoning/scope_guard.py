"""Scope guard for analyst questions: the tool answers questions about WORK ACTIVITY in the logs only.

Questions about protected or personal characteristics (sexual orientation, religion, caste/ethnicity,
health, pregnancy, politics, relationships, etc.) are refused BEFORE any model is called, because:
  * the logs (logins, USB, files, email, web) cannot answer them, so any answer would be invented;
  * a language model asked anyway may speculate about a real person;
  * profiling employees on these grounds is unethical and unlawful in most jurisdictions.

This keyword layer is deliberately conservative (it can refuse an innocent question that merely
mentions such a word; the refusal says how to rephrase). The LLM prompt carries the same rule as a
second layer for rephrasings the keywords miss (see reasoning/qa.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES: dict[str, tuple[str, ...]] = {
    "sexual orientation or gender identity": (
        r"\bgay\b", r"\blesbian", r"\bhomo(sexual)?\b", r"\bbisexual", r"\bqueer", r"\btrans(gender)?\b", r"\blgbt",
        r"sexual(ity| orientation| preference)", r"\b(likes?|into|attracted to) (men|women|guys|girls|boys)\b",
    ),
    "religion or belief": (
        r"\breligio", r"\bmuslim", r"\bhindu", r"\bchristian", r"\bjew(ish)?\b", r"\bsikh", r"\bbuddhis", r"\batheis",
        r"\bpray", r"\bmosque", r"\bchurch", r"\btemple\b", r"\bfaith\b", r"\bnamaz", r"\bfasting\b",
    ),
    "caste, race or ethnicity": (r"\bcaste\b", r"\brac(e|ial|ist)\b", r"\bethnic", r"\bdalit", r"\bbrahmin", r"\bskin colou?r", r"\bnationality\b"),
    "health or disability": (
        r"\bpregnan", r"\bdisab", r"\bmental(ly)? (ill|health)", r"\bdepress", r"\banxiety\b", r"\bhiv\b", r"\bcancer\b",
        r"\billness\b", r"\bdisease\b", r"\bmedical (condition|history)", r"\bon medication\b", r"\bsick\b",
    ),
    "political opinion or union membership": (r"\bpolitic", r"\bvot(e|es|ed|ing) for\b", r"\b(bjp|congress party|aap|democrat|republican)\b", r"\bunion member"),
    "private life or relationships": (
        r"\b(girl|boy)friend\b", r"\bdating\b", r"\baffair\b", r"\bdivorc", r"\bmarried\b", r"\bsex life\b", r"\bhooking up\b",
    ),
    "appearance or age": (r"\b(ugly|attractive|good.looking|fat)\b", r"\bhow old\b", r"\b(his|her|their) age\b"),
}
_COMPILED = {cat: [re.compile(p, re.IGNORECASE) for p in pats] for cat, pats in CATEGORIES.items()}


@dataclass
class ScopeDecision:
    in_scope: bool
    category: str | None = None
    message: str | None = None


def check_scope(question: str) -> ScopeDecision:
    q = (question or "").strip()
    if not q:
        return ScopeDecision(False, "empty", "Please type a question about this person's work activity.")
    for cat, pats in _COMPILED.items():
        if any(p.search(q) for p in pats):
            return ScopeDecision(False, cat, refusal(cat))
    return ScopeDecision(True)


def refusal(category: str) -> str:
    return (f"I can't answer questions about a person's {category}. This tool only looks at work activity in the "
            "logs (logins, USB devices, files, email and websites), and using personal characteristics to judge "
            "someone would be unfair and, in most places, unlawful. If you meant an activity, ask about the "
            "activity itself, for example: \"Did this person email anyone outside the company late at night?\"")


def not_in_logs(question: str = "") -> str:
    """Neutral reply for questions the logs simply cannot answer (no ethics lecture needed)."""
    return ("The logs don't record that. They only show work activity: logins and computers used, USB drives being "
            "plugged in or removed, files opened, emails sent and websites visited. Try asking about one of those.")
