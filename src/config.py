"""Runtime settings, read from environment variables.

No secret has a default value in source code. The API key (if any) is read
from the ``API_KEY`` environment variable at start-up only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECTOR_VERSION = "1.0.0"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Environment variable {name} must be a boolean, got {raw!r}")


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"Environment variable {name} must be >= {minimum}, got {value}")
    return value


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    path = Path(raw)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _env_optional_str(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    return raw.strip()


@dataclass(frozen=True)
class Settings:
    """All tunable settings of the service. Immutable once created."""

    patterns_path: Path = PROJECT_ROOT / "config" / "patterns.json"
    policies_path: Path = PROJECT_ROOT / "config" / "policies.json"
    corpus_path: Path = PROJECT_ROOT / "evaluation" / "corpus.json"

    audit_log_path: Path = PROJECT_ROOT / "logs" / "audit.jsonl"
    audit_max_bytes: int = 5_000_000
    audit_backup_count: int = 5
    audit_hash_input: bool = True
    audit_hash_key: str | None = field(default=None, repr=False)
    audit_log_raw_input: bool = False
    audit_log_client_ip: bool = False

    max_input_chars: int = 20_000
    max_body_bytes: int = 256_000
    max_trace_steps: int = 5_000

    api_key: str | None = field(default=None, repr=False)
    cors_origins: tuple[str, ...] = ("http://localhost:8501", "http://127.0.0.1:8501")
    rate_limit_per_minute: int = 120
    rule_editing_enabled: bool = False

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key)

    @classmethod
    def from_env(cls) -> "Settings":
        cors_raw = os.environ.get("CORS_ORIGINS")
        cors = (
            tuple(o.strip() for o in cors_raw.split(",") if o.strip())
            if cors_raw is not None
            else cls.cors_origins
        )
        return cls(
            patterns_path=_env_path("PATTERNS_PATH", cls.patterns_path),
            policies_path=_env_path("POLICIES_PATH", cls.policies_path),
            corpus_path=_env_path("CORPUS_PATH", cls.corpus_path),
            audit_log_path=_env_path("AUDIT_LOG_PATH", cls.audit_log_path),
            audit_max_bytes=_env_int("AUDIT_MAX_BYTES", cls.audit_max_bytes, minimum=10_000),
            audit_backup_count=_env_int("AUDIT_BACKUP_COUNT", cls.audit_backup_count, minimum=1),
            audit_hash_input=_env_bool("AUDIT_HASH_INPUT", cls.audit_hash_input),
            audit_hash_key=_env_optional_str("AUDIT_HASH_KEY"),
            audit_log_raw_input=_env_bool("AUDIT_LOG_RAW_INPUT", cls.audit_log_raw_input),
            audit_log_client_ip=_env_bool("AUDIT_LOG_CLIENT_IP", cls.audit_log_client_ip),
            max_input_chars=_env_int("MAX_INPUT_CHARS", cls.max_input_chars, minimum=1),
            max_body_bytes=_env_int("MAX_BODY_BYTES", cls.max_body_bytes, minimum=1_024),
            max_trace_steps=_env_int("MAX_TRACE_STEPS", cls.max_trace_steps, minimum=1),
            api_key=_env_optional_str("API_KEY"),
            cors_origins=cors,
            rate_limit_per_minute=_env_int("RATE_LIMIT_PER_MINUTE", cls.rate_limit_per_minute),
            rule_editing_enabled=_env_bool("RULE_EDITING_ENABLED", cls.rule_editing_enabled),
        )
