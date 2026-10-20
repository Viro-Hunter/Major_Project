"""LLM provider registry: detect a provider from an API key, verify the key, list
models, and recommend one.

Flow used by the dashboard (api/routes/llm.py):

    paste key -> detect_provider(key)            # instant, offline: prefix rules
              -> check_credentials(provider, key) # network: is the key valid? paid or free?
              -> catalog + recommend()            # paid models if the key can pay, else best free

OpenRouter is the primary target (one key -> hundreds of models, many free).
Anthropic, OpenAI, Groq, Gemini and xAI keys are recognised too; everything except
Anthropic is called through the OpenAI-compatible chat API.

Paid vs free on OpenRouter
    GET /api/v1/key      -> {"data": {"is_free_tier", "limit", "limit_remaining", "usage", ...}}
    GET /api/v1/credits  -> {"data": {"total_credits", "total_usage"}}   (best effort)
    GET /api/v1/models   -> {"data": [{"id", "name", "context_length", "pricing": {"prompt", "completion"}}]}
    A key "can pay" when the account has bought credits (not free tier), has credit
    left, and the key's own spending cap (if any) is not exhausted.  Free models are
    the ones whose prompt and completion price are both 0 (ids usually end ":free").

Choosing "the better" model
    Paid: first available family from PAID_PREFERENCE (quality per cost for short JSON
    verdicts), newest version within the family.
    Free: scored by a family bonus (models known to follow JSON instructions well),
    parameter count parsed from the id (e.g. "70b"), and context length; thinking-only
    models are penalised because they are slow and often wrap the JSON in reasoning.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
APP_HEADERS = {"HTTP-Referer": "https://github.com/Viro-Hunter/Major_Project", "X-Title": "Cyber Intelligence GraphRAG"}

# Rough size of one verdict call, used only to show an estimated cost per verdict.
EST_PROMPT_TOKENS = 3000
EST_COMPLETION_TOKENS = 400


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    kind: str                      # "openai" (OpenAI-compatible) | "anthropic"
    base_url: Optional[str]
    key_pattern: Optional[str]     # regex on the raw key
    has_free_models: bool
    docs: str


PROVIDERS: dict[str, Provider] = {p.id: p for p in (
    Provider("openrouter", "OpenRouter", "openai", OPENROUTER_BASE, r"^sk-or-", True, "https://openrouter.ai/keys"),
    Provider("anthropic", "Anthropic", "anthropic", None, r"^sk-ant-", False, "https://console.anthropic.com/settings/keys"),
    Provider("groq", "Groq", "openai", "https://api.groq.com/openai/v1", r"^gsk_", True, "https://console.groq.com/keys"),
    Provider("gemini", "Google Gemini", "openai", "https://generativelanguage.googleapis.com/v1beta/openai", r"^AIza[0-9A-Za-z_\-]{20,}$", True, "https://aistudio.google.com/apikey"),
    Provider("xai", "xAI", "openai", "https://api.x.ai/v1", r"^xai-", False, "https://console.x.ai"),
    # OpenAI last: its "sk-" prefix is a superset of sk-or- / sk-ant-.
    Provider("openai", "OpenAI", "openai", "https://api.openai.com/v1", r"^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}$", False, "https://platform.openai.com/api-keys"),
    Provider("ollama", "Local Ollama", "openai", "http://localhost:11434/v1", None, True, "https://ollama.com"),
)}
DETECTION_ORDER = ("openrouter", "anthropic", "groq", "gemini", "xai", "openai")


def mask_key(key: str) -> str:
    key = (key or "").strip()
    return f"{key[:6]}…{key[-4:]}" if len(key) > 12 else "…"


def detect_provider(api_key: str) -> dict[str, Any]:
    """Offline, prefix-based detection. Never sends the key anywhere."""
    key = (api_key or "").strip()
    if not key:
        return {"provider": None, "label": None, "certain": False, "message": "Paste an API key to detect its provider."}
    if re.search(r"\s", key):
        return {"provider": None, "label": None, "certain": False, "message": "The key contains spaces or line breaks — paste it again."}
    for pid in DETECTION_ORDER:
        p = PROVIDERS[pid]
        if p.key_pattern and re.search(p.key_pattern, key):
            return {"provider": pid, "label": p.label, "certain": pid != "openai" or key.startswith("sk-proj-"),
                    "message": f"Looks like an {p.label} key." if p.label[0] in "AEIOU" else f"Looks like a {p.label} key."}
    return {"provider": None, "label": None, "certain": False,
            "message": "Unrecognised key format. Choose the provider manually."}


# --------------------------------------------------------------------------- #
# HTTP (injectable for tests)
# --------------------------------------------------------------------------- #
HttpGet = Callable[[str, dict[str, str]], httpx.Response]


def _default_get(url: str, headers: dict[str, str]) -> httpx.Response:
    return httpx.get(url, headers=headers, timeout=15.0)


_http_get: HttpGet = _default_get


def set_http_get(fn: Optional[HttpGet]) -> None:
    """Tests swap the transport; ``None`` restores the real one."""
    global _http_get
    _http_get = fn or _default_get


def _auth_headers(provider: Provider, key: str) -> dict[str, str]:
    if provider.kind == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    h = {"Authorization": f"Bearer {key}"}
    if provider.id == "openrouter":
        h.update(APP_HEADERS)
    return h


# --------------------------------------------------------------------------- #
# Model catalog
# --------------------------------------------------------------------------- #
@dataclass
class ModelInfo:
    id: str
    name: str
    free: bool
    context_length: Optional[int] = None
    prompt_price: Optional[float] = None       # USD per token
    completion_price: Optional[float] = None
    est_cost_per_verdict: Optional[float] = None
    score: float = 0.0
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in ("id", "name", "free", "context_length", "prompt_price",
                                              "completion_price", "est_cost_per_verdict", "score", "tags")}


def _price(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _params_billions(model_id: str) -> float:
    """'meta-llama/llama-3.3-70b-instruct:free' -> 70; '...-235b-a22b' -> 235; unknown -> 0."""
    m = re.findall(r"(\d+(?:\.\d+)?)\s*[bB](?![a-zA-Z])", model_id.replace("_", "-"))
    return max((float(x) for x in m), default=0.0)


# Families that reliably follow "respond with JSON only" for this task (best first).
FREE_FAMILY_BONUS = (
    (r"deepseek.*(chat|v3)", 30), (r"qwen.?3", 28), (r"llama-?4", 26), (r"gpt-oss", 26),
    (r"llama-3\.3-70b|llama-3\.1-405b", 25), (r"gemini.*flash", 24), (r"qwen-?2\.5-(72|32)b", 22),
    (r"mistral-(small|medium|large)", 18), (r"gemma-?3", 14), (r"llama", 10), (r"qwen", 10), (r"mistral", 8),
)
FREE_PENALTY = ((r"(^|[/-])r1\b|thinking|reason", 12), (r"vision|-vl\b|embed|guard|tts|whisper|image", 60))

# Paid: quality-per-cost for short structured verdicts. First family present wins.
PAID_PREFERENCE = (
    r"anthropic/claude-(sonnet|3\.7-sonnet|3\.5-sonnet)", r"^claude-(sonnet|3-7-sonnet|3-5-sonnet)",
    r"openai/gpt-4\.1-mini|openai/gpt-4o-mini|openai/gpt-5-mini", r"^gpt-4\.1-mini|^gpt-4o-mini|^gpt-5-mini",
    r"google/gemini-2\.5-flash|google/gemini-.*flash", r"gemini-2\.5-flash|gemini-.*flash",
    r"deepseek/deepseek-chat", r"llama-3\.3-70b-versatile", r"grok-.*mini|grok-3",
)


def score_free_model(m: ModelInfo) -> float:
    mid = m.id.lower()
    s = next((bonus for pat, bonus in FREE_FAMILY_BONUS if re.search(pat, mid)), 0)
    s += min(20.0, 6.0 * math.log10(1 + _params_billions(mid)))       # 70B -> ~11, 400B -> ~16
    s += min(10.0, 2.5 * math.log2(1 + (m.context_length or 8192) / 8192))
    s -= sum(p for pat, p in FREE_PENALTY if re.search(pat, mid))
    return round(s, 2)


def _version_key(model_id: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", model_id)[:6])


def recommend(models: list[ModelInfo], can_pay: bool) -> Optional[ModelInfo]:
    if can_pay:
        paid = [m for m in models if not m.free]
        for pat in PAID_PREFERENCE:
            hits = [m for m in paid if re.search(pat, m.id.lower())]
            if hits:
                return max(hits, key=lambda m: _version_key(m.id))
        if paid:
            return paid[0]
    free = [m for m in models if m.free]
    return max(free, key=lambda m: m.score) if free else (models[0] if models else None)


def _openrouter_models(key: str) -> list[ModelInfo]:
    r = _http_get(f"{OPENROUTER_BASE}/models", _auth_headers(PROVIDERS["openrouter"], key))
    r.raise_for_status()
    out = []
    for d in r.json().get("data", []):
        pr = d.get("pricing") or {}
        p, c = _price(pr.get("prompt")), _price(pr.get("completion"))
        if p is None or c is None or p < 0 or c < 0:   # -1 = variable-price router models
            continue
        free = p == 0 and c == 0
        m = ModelInfo(id=d["id"], name=d.get("name") or d["id"], free=free, context_length=d.get("context_length"),
                      prompt_price=p, completion_price=c,
                      est_cost_per_verdict=round(EST_PROMPT_TOKENS * p + EST_COMPLETION_TOKENS * c, 6))
        m.score = score_free_model(m) if free else 0.0
        out.append(m)
    return out


def _generic_models(provider: Provider, key: str) -> list[ModelInfo]:
    url = "https://api.anthropic.com/v1/models?limit=100" if provider.kind == "anthropic" else f"{provider.base_url}/models"
    r = _http_get(url, _auth_headers(provider, key))
    r.raise_for_status()
    out = []
    for d in r.json().get("data", []):
        mid = str(d.get("id", "")).removeprefix("models/")
        if not mid or re.search(r"embed|whisper|tts|dall-e|moderation|audio|realtime|transcribe|image|search", mid.lower()):
            continue
        m = ModelInfo(id=mid, name=d.get("display_name") or mid, free=provider.has_free_models,
                      context_length=d.get("context_window") or d.get("context_length"))
        m.score = score_free_model(m) if m.free else 0.0
        out.append(m)
    return out


# --------------------------------------------------------------------------- #
# Credential check
# --------------------------------------------------------------------------- #
def check_credentials(api_key: str, provider_id: Optional[str] = None) -> dict[str, Any]:
    """Verify a key and return {valid, provider, tier, can_pay, credits, models, recommended, message}."""
    key = (api_key or "").strip()
    provider_id = provider_id or detect_provider(key)["provider"]
    if provider_id not in PROVIDERS or provider_id == "ollama":
        return {"valid": False, "provider": provider_id, "message": "Unknown provider — pick one from the list."}
    provider = PROVIDERS[provider_id]
    base = {"provider": provider.id, "label": provider.label, "key_hint": mask_key(key)}
    try:
        if provider.id == "openrouter":
            r = _http_get(f"{OPENROUTER_BASE}/key", _auth_headers(provider, key))
            if r.status_code == 404:  # older deployments
                r = _http_get(f"{OPENROUTER_BASE}/auth/key", _auth_headers(provider, key))
            if r.status_code in (401, 403):
                return {**base, "valid": False, "message": "OpenRouter rejected this key. Check it at openrouter.ai/keys."}
            r.raise_for_status()
            info = r.json().get("data", {}) or {}
            remaining = None
            try:
                c = _http_get(f"{OPENROUTER_BASE}/credits", _auth_headers(provider, key))
                if c.status_code == 200:
                    cd = c.json().get("data", {}) or {}
                    remaining = float(cd.get("total_credits", 0)) - float(cd.get("total_usage", 0))
            except (httpx.HTTPError, ValueError, TypeError):
                pass
            limit_remaining = info.get("limit_remaining")
            can_pay = (not info.get("is_free_tier", True)
                       and (remaining is None or remaining > 0)
                       and (limit_remaining is None or float(limit_remaining) > 0))
            models = _openrouter_models(key)
            credits = {"remaining_usd": None if remaining is None else round(remaining, 4),
                       "key_limit_remaining_usd": limit_remaining, "usage_usd": info.get("usage"),
                       "is_free_tier": info.get("is_free_tier")}
        else:
            models = _generic_models(provider, key)
            can_pay = not provider.has_free_models
            credits = {}
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        msg = "The provider rejected this key." if code in (401, 403) else f"The provider returned HTTP {code}."
        return {**base, "valid": False, "message": msg}
    except httpx.HTTPError as exc:
        return {**base, "valid": False, "message": f"Could not reach {provider.label}: {exc.__class__.__name__}. Check your internet connection."}

    if provider.id != "openrouter" and not models:
        return {**base, "valid": False, "message": f"{provider.label} accepted the key but listed no chat models."}
    rec = recommend(models, can_pay)
    visible = models if can_pay else [m for m in models if m.free]
    visible.sort(key=lambda m: (m.id != (rec.id if rec else ""), -m.score if m.free else 0, m.id))
    tier = "paid" if can_pay else "free"
    if provider.id == "openrouter":
        message = (f"Key valid with credit available — paid models unlocked; recommended {rec.id}." if can_pay and rec
                   else f"Key valid on the free tier — showing {len(visible)} free models; best pick {rec.id}." if rec
                   else "Key valid, but no free models are listed right now.")
    else:
        message = f"Key valid — {len(visible)} models available."
    return {**base, "valid": True, "tier": tier, "can_pay": can_pay, "credits": credits,
            "models": [m.as_dict() for m in visible], "recommended": rec.id if rec else None, "message": message}
