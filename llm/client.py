"""Week 4 — llm/client.py

Provider-agnostic LLM client. Dispatches to Anthropic or OpenAI based on the
``LLM_PROVIDER`` env var (read via python-dotenv), and transparently supports
any OpenAI-compatible endpoint (Ollama, LM Studio, Groq, ...) via
``OPENAI_API_BASE``.

Usage (env vars):
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
    """Thin, swappable wrapper around an LLM chat completion."""

    SUPPORTED = ("anthropic", "openai")

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.model = model or self._default_model()
        self.api_key = api_key or self._api_key_for(self.provider)
        self.base_url = base_url or os.getenv("OPENAI_API_BASE")
        self._session = None

    # ------------------------------------------------------------------ #
    def call(self, system_prompt: str, user_prompt: str) -> LLMResponse:
        """Chat completion with a system prompt and a user prompt."""
        if self.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        if self.provider == "openai":
            return self._call_openai(system_prompt, user_prompt)
        raise ValueError(
            f"Unsupported LLM_PROVIDER={self.provider!r}; choose from {self.SUPPORTED}"
        )

    # ------------------------------------------------------------------ #
    def _default_model(self) -> str:
        env_model = os.getenv("LLM_MODEL") or os.getenv("OPENAI_MODEL")
        if env_model:
            return env_model
        if self.provider == "anthropic":
            return "claude-3-5-sonnet-20241022"
        # Ollama default — low-RAM Qwen
        return "qwen2.5:3b"

    def _api_key_for(self, provider: str) -> str:
        key = os.getenv("ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY", "")
        if not key and provider == "openai":
            # Ollama-style local endpoints accept any non-empty placeholder.
            return "ollama"
        return key

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

        kwargs: dict = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = openai.OpenAI(**kwargs)
        completion = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=4096,
        )
        choices = completion.choices or []
        content = choices[0].message.content if choices else ""
        return LLMResponse(content=content or "", model=self.model, raw=completion)
