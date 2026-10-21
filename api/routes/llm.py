"""Model connection endpoints used by the dashboard's "Model" panel.

    POST /llm/detect      {api_key}                 -> provider guess (offline, nothing sent anywhere)
    POST /llm/connect     {api_key, provider?}      -> verify key, list models, activate the recommended one
    POST /llm/select      {model}                   -> switch model on the active connection
    GET  /llm/status                                -> what the reasoning engine will use right now
    POST /llm/test                                  -> one tiny round-trip to prove the model answers
    POST /llm/disconnect                            -> forget the key, fall back to .env / Ollama

The key lives in process memory only and is never returned in full (key_hint is masked).
"""
from __future__ import annotations

import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from llm import runtime
from llm.providers import PROVIDERS, check_credentials, detect_provider, mask_key

router = APIRouter(prefix="/llm", tags=["llm"])


class KeyBody(BaseModel):
    api_key: str = Field(min_length=1, max_length=400)
    provider: Optional[str] = None


class ModelBody(BaseModel):
    model: str = Field(min_length=1, max_length=200)


@router.get("/providers")
async def providers():
    return {"providers": [{"id": p.id, "label": p.label, "has_free_models": p.has_free_models, "keys_url": p.docs}
                          for p in PROVIDERS.values() if p.id != "ollama"]}


@router.post("/detect")
async def detect(body: KeyBody):
    return detect_provider(body.api_key)


@router.post("/connect")
def connect(body: KeyBody):
    result = check_credentials(body.api_key, body.provider)
    if result.get("valid") and result.get("recommended"):
        runtime.set_active(runtime.ActiveLLM(
            provider=result["provider"], api_key=body.api_key.strip(), model=result["recommended"],
            tier=result.get("tier", "unknown"), allowed_models=tuple(m["id"] for m in result["models"]),
            json_models=tuple(m["id"] for m in result["models"] if m.get("json_mode"))))
        result["active_model"] = result["recommended"]
    return result


@router.post("/select")
async def select(body: ModelBody):
    active = runtime.get_active()
    if active is None:
        raise HTTPException(409, "Connect an API key before choosing a model.")
    if active.allowed_models and body.model not in active.allowed_models:
        raise HTTPException(400, "That model is not available for this key"
                                 + (" (free tier: only free models)." if active.tier == "free" else "."))
    runtime.set_model(body.model)
    return await status()


@router.get("/status")
async def status():
    active = runtime.get_active()
    offline = os.getenv("CYBERGRAPHRAG_OFFLINE", "").lower() in ("1", "true", "yes")
    if active is not None:
        return {"source": "dashboard", "provider": active.provider, "label": PROVIDERS[active.provider].label,
                "model": active.model, "tier": active.tier, "key_hint": mask_key(active.api_key), "offline": False}
    from llm.client import LLMClient

    try:
        c = LLMClient()
        provider, model, hint = c.provider, c.model, mask_key(c.api_key) if c.api_key not in ("", "ollama") else None
    except Exception as exc:  # misconfigured .env should not break the dashboard
        provider, model, hint = os.getenv("LLM_PROVIDER", "openai"), f"unavailable ({exc.__class__.__name__})", None
    label = PROVIDERS["ollama"].label if (provider in ("openai", "ollama") and "11434" in str(os.getenv("OPENAI_API_BASE", "11434"))) \
        else PROVIDERS.get(provider, PROVIDERS["openai"]).label
    return {"source": "env", "provider": provider, "label": label, "model": model, "tier": "unknown",
            "key_hint": hint, "offline": offline}


@router.post("/test")
def test():
    from llm.client import LLMClient

    t0 = time.perf_counter()
    try:
        c = LLMClient()
        r = c.call("Reply with JSON only.", 'Return exactly {"ok": true}')
        ok = '"ok"' in r.content and "true" in r.content.lower()
        return {"ok": ok, "model": c.model, "latency_ms": round(1000 * (time.perf_counter() - t0)),
                "reply": r.content[:200]}
    except Exception as exc:
        msg = str(exc)
        hint = (" Free models are rate-limited; wait a minute or pick another." if "429" in msg
                else " This model may need credits." if "402" in msg else "")
        return {"ok": False, "latency_ms": round(1000 * (time.perf_counter() - t0)),
                "error": f"{exc.__class__.__name__}: {msg[:200]}{hint}"}


@router.post("/disconnect")
async def disconnect():
    runtime.clear()
    return await status()
