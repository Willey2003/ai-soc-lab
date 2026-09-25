"""Runtime settings, read once from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # Where alerts come from
    alerts_file: Path = field(
        default_factory=lambda: Path(
            os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
        )
    )
    tail_enabled: bool = field(default_factory=lambda: _bool("TAIL_ENABLED", True))
    start_at_end: bool = field(default_factory=lambda: _bool("START_AT_END", True))
    poll_seconds: float = field(default_factory=lambda: float(os.getenv("POLL_SECONDS", "2")))
    min_rule_level: int = field(default_factory=lambda: int(os.getenv("MIN_RULE_LEVEL", "7")))

    # Where results go
    db_path: Path = field(
        default_factory=lambda: Path(os.getenv("DB_PATH", "/var/lib/soc-triage/triage.db"))
    )

    # AI backends, tried in order until one answers
    providers: list[str] = field(
        default_factory=lambda: _list("LLM_PROVIDERS", "ollama,heuristic")
    )
    llm_timeout: float = field(default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "60")))

    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://ollama:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2:3b"))

    # Any OpenAI-compatible hosted API (Groq by default: free tier, very fast)
    hosted_url: str = field(
        default_factory=lambda: os.getenv(
            "HOSTED_API_URL", "https://api.groq.com/openai/v1/chat/completions"
        )
    )
    hosted_model: str = field(
        default_factory=lambda: os.getenv("HOSTED_MODEL", "llama-3.1-8b-instant")
    )
    hosted_api_key: str = field(default_factory=lambda: os.getenv("HOSTED_API_KEY", ""))

    # Privacy: redact before anything leaves the box for a hosted API
    redact_for_hosted: bool = field(default_factory=lambda: _bool("REDACT_FOR_HOSTED", True))

    # HTTP API
    bind_host: str = field(default_factory=lambda: os.getenv("BIND_HOST", "0.0.0.0"))
    bind_port: int = field(default_factory=lambda: int(os.getenv("BIND_PORT", "8020")))
    api_key: str = field(default_factory=lambda: os.getenv("TRIAGE_API_KEY", ""))
