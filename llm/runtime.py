"""Active LLM connection chosen from the dashboard, held in process memory only.

The key pasted in the dashboard is never written to disk or logged; restarting the
API forgets it and the client falls back to .env (or local Ollama). To make a key
permanent, put it in .env (see .env.example).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class ActiveLLM:
    provider: str
    api_key: str
    model: str
    tier: str = "unknown"          # "paid" | "free" | "unknown"
    allowed_models: tuple[str, ...] = ()


_lock = threading.Lock()
_active: Optional[ActiveLLM] = None


def set_active(cfg: ActiveLLM) -> None:
    global _active
    with _lock:
        _active = cfg


def get_active() -> Optional[ActiveLLM]:
    with _lock:
        return _active


def set_model(model: str) -> None:
    with _lock:
        if _active is None:
            raise RuntimeError("no dashboard connection is active")
        _active.model = model


def clear() -> None:
    global _active
    with _lock:
        _active = None
