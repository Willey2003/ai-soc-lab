"""Pluggable AI backends. Each returns the model's raw text; triage.py parses it.

- ollama:    local, private, free, no limits beyond your hardware.
- hosted:    any OpenAI-compatible chat API. Default is Groq (free tier, very
             fast). Gemini, OpenRouter, Cerebras etc. work by changing the URL.
- heuristic: no model at all; always succeeds, so triage never stalls.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Protocol

import requests

from .config import Settings

LOG = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    pass


@dataclass
class Completion:
    provider: str
    model: str
    text: str
    latency_ms: int


class Provider(Protocol):
    name: str
    sends_data_offsite: bool

    def complete(self, system: str, user: str) -> Completion: ...


class OllamaProvider:
    name = "ollama"
    sends_data_offsite = False

    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.url = settings.ollama_url.rstrip("/") + "/api/chat"
        self.model = settings.ollama_model
        self.timeout = settings.llm_timeout
        self.http = session or requests.Session()

    def complete(self, system: str, user: str) -> Completion:
        start = time.monotonic()
        try:
            resp = self.http.post(
                self.url,
                json={
                    "model": self.model,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            text = resp.json()["message"]["content"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise ProviderError(f"ollama: {exc}") from exc
        return Completion(self.name, self.model, text, int((time.monotonic() - start) * 1000))


class HostedProvider:
    """OpenAI-compatible /chat/completions endpoint."""

    name = "hosted"
    sends_data_offsite = True

    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.url = settings.hosted_url
        self.model = settings.hosted_model
        self.key = settings.hosted_api_key
        self.timeout = settings.llm_timeout
        self.http = session or requests.Session()
        self._cooldown_until = 0.0

    def complete(self, system: str, user: str) -> Completion:
        if not self.key:
            raise ProviderError("hosted: HOSTED_API_KEY is not set")
        if time.monotonic() < self._cooldown_until:
            raise ProviderError("hosted: rate limited, cooling down")
        start = time.monotonic()
        try:
            resp = self.http.post(
                self.url,
                headers={"Authorization": f"Bearer {self.key}"},
                json={
                    "model": self.model,
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=self.timeout,
            )
            if resp.status_code == 429:
                wait = float(resp.headers.get("retry-after", "30") or 30)
                self._cooldown_until = time.monotonic() + wait
                raise ProviderError(f"hosted: 429 rate limited for {wait:.0f}s")
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"]
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            raise ProviderError(f"hosted: {exc}") from exc
        return Completion(self.name, self.model, text, int((time.monotonic() - start) * 1000))


class HeuristicProvider:
    """Signals the triage engine to use the rule-based baseline verdict."""

    name = "heuristic"
    sends_data_offsite = False
    model = "rules"

    def complete(self, system: str, user: str) -> Completion:
        return Completion(self.name, self.model, json.dumps({"use_baseline": True}), 0)


def build_providers(settings: Settings) -> list[Provider]:
    registry = {"ollama": OllamaProvider, "hosted": HostedProvider, "heuristic": HeuristicProvider}
    providers: list[Provider] = []
    for name in settings.providers:
        cls = registry.get(name)
        if cls is None:
            raise ValueError(f"unknown provider {name!r}; choose from {sorted(registry)}")
        providers.append(cls() if cls is HeuristicProvider else cls(settings))
    if not any(p.name == "heuristic" for p in providers):
        providers.append(HeuristicProvider())
    return providers
