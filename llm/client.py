"""Week 4 — llm/client.py

Provider-agnostic LLM client. Dispatches to Anthropic or OpenAI based on the
``LLM_PROVIDER`` env var (read via python-dotenv), and transparently supports
any OpenAI-compatible endpoint (Ollama, LM Studio, Groq, ...) via
``OPENAI_API_BASE``.

The dashboard can also set the provider/key/model at runtime (llm/runtime.py),
which takes precedence over the environment.

Usage (env vars):
    LLM_PROVIDER=openrouter OPENROUTER_API_KEY=sk-or-...    [OPENROUTER_MODEL=auto picks best for the key]
    LLM_PROVIDER=anthropic  ANTHROPIC_API_KEY=sk-ant-...   [model: claude-3-5-sonnet]
    LLM_PROVIDER=openai     OPENAI_API_KEY=sk-...          [model: gpt-4-turbo]
    LLM_PROVIDER=openai     OPENAI_API_BASE=http://localhost:11434/v1   (Ollama)
                            OPENAI_API_KEY=ollama          (any placeholder)
                            OPENAI_MODEL=qwen2.5:3b

Tests inject a provider via ``LLMClient(provider="mock", model="test")`` —
see tests/test_entity_extractor.py.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


@dataclass
class LLMResponse:
    """Uniform response shape returned by every provider."""

    content: str
    model: str
    raw: Optional[object] = field(default=None, repr=False)


class LLMClient:
    """Thin, swappable wrapper around an LLM chat completion.

    Resolution order for provider / key / model:
      1. explicit constructor arguments
      2. the connection made in the dashboard (llm/runtime.py, in memory)
      3. environment (.env): LLM_PROVIDER + the provider's key/model variables
      4. local Ollama (OpenAI-compatible, no key)

    Providers: anthropic | openai | openrouter | groq | gemini | xai | ollama.
    Everything except anthropic goes through the OpenAI-compatible chat API.
    ``OPENROUTER_MODEL=auto`` picks the recommended model for the key on first use.
    """

    SUPPORTED = ("anthropic", "openai", "openrouter", "groq", "gemini", "xai", "ollama")
    _ENV_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "openrouter": "OPENROUTER_API_KEY",
                 "groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "xai": "XAI_API_KEY"}
    _ENV_MODELS = {"openrouter": "OPENROUTER_MODEL", "openai": "OPENAI_MODEL", "anthropic": "LLM_MODEL",
                   "groq": "GROQ_MODEL", "gemini": "GEMINI_MODEL", "xai": "XAI_MODEL"}
    _auto_cache: dict = {}

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        from llm.runtime import get_active

        active = None if (provider or api_key) else get_active()
        if active is not None:
            self.provider, self.api_key, self.model = active.provider, active.api_key, model or active.model
            self.source = "dashboard"
        else:
            self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
            self.api_key = api_key or self._api_key_for(self.provider)
            self.model = model or self._default_model()
            self.source = "env"
        self.base_url = base_url or self._base_url_for(self.provider)
        self._session = None

    # ------------------------------------------------------------------ #
    def call(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Chat completion with a system prompt and a user prompt."""
        if self.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        if self.provider in self.SUPPORTED:
            return self._call_openai(system_prompt, user_prompt)
        raise ValueError(
            f"Unsupported LLM_PROVIDER={self.provider!r}; choose from {self.SUPPORTED}"
        )

    # ------------------------------------------------------------------ #
    def _default_model(self) -> str:
        env_name = self._ENV_MODELS.get(self.provider)
        env_model = (os.getenv(env_name) if env_name else None) or os.getenv("LLM_MODEL") or (
            os.getenv("OPENAI_MODEL") if self.provider in ("openai", "ollama") else None)
        if self.provider == "openrouter" and (not env_model or env_model == "auto"):
            return self._auto_model()
        if env_model:
            return env_model
        if self.provider == "anthropic":
            return "claude-3-5-sonnet-20241022"
        # Ollama default — low-RAM Qwen
        return "qwen2.5:3b"

    def _auto_model(self) -> str:
        """Ask OpenRouter which model this key should use (cached per key)."""
        if self.api_key in self._auto_cache:
            return self._auto_cache[self.api_key]
        fallback = "meta-llama/llama-3.3-70b-instruct:free"
        try:
            from llm.providers import check_credentials

            res = check_credentials(self.api_key, "openrouter")
            model = res.get("recommended") if res.get("valid") else None
        except Exception:
            model = None
        self._auto_cache[self.api_key] = model or fallback
        return self._auto_cache[self.api_key]

    def _api_key_for(self, provider: str) -> str:
        env_name = self._ENV_KEYS.get(provider)
        key = os.getenv(env_name, "") if env_name else ""
        if not key and provider == "openrouter":
            key = os.getenv("LLM_API_KEY", "")
        if not key and provider in ("openai", "ollama"):
            # Ollama-style local endpoints accept any non-empty placeholder.
            return "ollama"
        return key

    def _base_url_for(self, provider: str) -> Optional[str]:
        from llm.providers import PROVIDERS

        if provider == "openai":
            return os.getenv("OPENAI_API_BASE") or None
        if provider == "ollama":
            return os.getenv("OPENAI_API_BASE") or PROVIDERS["ollama"].base_url
        p = PROVIDERS.get(provider)
        return p.base_url if p else None

    # ------------------------------------------------------------------ #
    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return LLMResponse(
            content=message.content[0].text, model=self.model, raw=message
        )

    def _call_openai(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        import openai

        kwargs: dict = {"api_key": self.api_key or "none", "timeout": 90.0, "max_retries": 1}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        if self.provider == "openrouter":
            from llm.providers import APP_HEADERS

            kwargs["default_headers"] = APP_HEADERS
        client = openai.OpenAI(**kwargs)
        completion = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=2048,
        )
        choices = completion.choices or []
        content = choices[0].message.content if choices else ""
        return LLMResponse(content=content or "", model=self.model, raw=completion)
