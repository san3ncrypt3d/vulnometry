"""Configuration. Every credential is optional."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_VERSION = "0.1.0"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _flag(name: str, default: bool = False) -> bool:
    raw = _env(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: float) -> float:
    try:
        return float(_env(name) or default)
    except (TypeError, ValueError):
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except (TypeError, ValueError):
        return default


def _state_home() -> Path:
    base = _env("XDG_STATE_HOME") or os.path.join(str(Path.home()), ".local", "state")
    return Path(base) / "vulnometry"


@dataclass
class Settings:
    nvd_api_key: str | None = None
    github_token: str | None = None

    timeout: float = 25.0
    max_retries: int = 3
    user_agent: str = f"vulnometry/{_VERSION} (exposure measurement)"
    offline: bool = False

    state_dir: Path = field(default_factory=_state_home)
    cache_enabled: bool = True
    history_enabled: bool = True

    inventory_path: str | None = None

    # Minutes a human spends triaging one finding by hand: read the CVE, find
    # where it runs, judge whether it matters, write it up or close it. Reported
    # as a band because it genuinely varies that much. Only ever used to put a
    # figure on effort avoided; never feeds a score.
    triage_minutes_low: float = 30.0
    triage_minutes_high: float = 120.0

    default_model: str | None = None
    ollama_host: str = "http://localhost:11434"
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    azure_endpoint: str | None = None
    azure_api_key: str | None = None
    azure_api_version: str = "2024-10-21"
    aws_region: str | None = None
    aws_profile: str | None = None
    anthropic_api_key: str | None = None
    anthropic_base_url: str = "https://api.anthropic.com"
    google_api_key: str | None = None
    onprem_base_url: str = "http://localhost:8000/v1"
    onprem_api_key: str = "not-needed"

    max_tokens: int = 2048
    temperature: float = 0.1
    max_turns: int = 8

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            nvd_api_key=_env("NVD_API_KEY"),
            github_token=_env("GITHUB_TOKEN") or _env("GH_TOKEN"),
            timeout=_num("VULNOMETRY_TIMEOUT", 25.0),
            max_retries=_int("VULNOMETRY_MAX_RETRIES", 3),
            user_agent=_env("VULNOMETRY_USER_AGENT") or cls.user_agent,
            offline=_flag("VULNOMETRY_OFFLINE", False),
            state_dir=Path(_env("VULNOMETRY_STATE_DIR") or _state_home()),
            cache_enabled=not _flag("VULNOMETRY_NO_CACHE", False),
            history_enabled=not _flag("VULNOMETRY_NO_HISTORY", False),
            inventory_path=_env("VULNOMETRY_INVENTORY"),
            triage_minutes_low=_num("VULNOMETRY_TRIAGE_MINUTES_LOW", 30.0),
            triage_minutes_high=_num("VULNOMETRY_TRIAGE_MINUTES_HIGH", 120.0),
            default_model=_env("VULNOMETRY_MODEL"),
            ollama_host=(_env("OLLAMA_HOST") or "http://localhost:11434").rstrip("/"),
            openai_api_key=_env("OPENAI_API_KEY"),
            openai_base_url=(_env("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/"),
            azure_endpoint=(_env("AZURE_AI_ENDPOINT") or _env("AZURE_OPENAI_ENDPOINT") or "").rstrip("/") or None,
            azure_api_key=_env("AZURE_AI_API_KEY") or _env("AZURE_OPENAI_API_KEY"),
            azure_api_version=_env("AZURE_OPENAI_API_VERSION") or "2024-10-21",
            aws_region=_env("AWS_REGION") or _env("AWS_DEFAULT_REGION"),
            aws_profile=_env("AWS_PROFILE"),
            anthropic_api_key=_env("ANTHROPIC_API_KEY"),
            anthropic_base_url=(_env("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/"),
            google_api_key=_env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY"),
            onprem_base_url=(_env("VULNOMETRY_ONPREM_BASE_URL") or "http://localhost:8000/v1").rstrip("/"),
            onprem_api_key=_env("VULNOMETRY_ONPREM_API_KEY") or "not-needed",
            max_tokens=_int("VULNOMETRY_MAX_TOKENS", 2048),
            temperature=_num("VULNOMETRY_TEMPERATURE", 0.1),
            max_turns=_int("VULNOMETRY_MAX_TURNS", 8),
        )


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
