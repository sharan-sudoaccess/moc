from __future__ import annotations

import shutil
import sys
import warnings
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

warnings.filterwarnings("ignore", message=".*httpx.*", category=DeprecationWarning)

from src.config import Settings  # noqa: E402
from src.detector import PromptInjectionDetector  # noqa: E402
from src.rules import load_ruleset, parse_ruleset  # noqa: E402
from src.scoring import load_scoring_config  # noqa: E402
from src.service import DetectionService  # noqa: E402


@pytest.fixture()
def tmp_config(tmp_path: Path) -> Path:
    """A private copy of config/ so tests can mutate rules safely."""
    cfg = tmp_path / "config"
    shutil.copytree(PROJECT_ROOT / "config", cfg)
    return cfg


@pytest.fixture()
def settings(tmp_path: Path, tmp_config: Path) -> Settings:
    return Settings(
        patterns_path=tmp_config / "patterns.json",
        policies_path=tmp_config / "policies.json",
        corpus_path=PROJECT_ROOT / "evaluation" / "corpus.json",
        audit_log_path=tmp_path / "logs" / "audit.jsonl",
        rate_limit_per_minute=0,
        rule_editing_enabled=True,
    )


@pytest.fixture()
def service(settings: Settings) -> DetectionService:
    svc = DetectionService(settings)
    yield svc
    svc.audit.close()


@pytest.fixture(scope="session")
def detector() -> PromptInjectionDetector:
    return PromptInjectionDetector(load_ruleset(PROJECT_ROOT / "config" / "patterns.json"))


@pytest.fixture(scope="session")
def scoring_config():
    return load_scoring_config(PROJECT_ROOT / "config" / "policies.json")


def make_ruleset(rules: list[dict], ignorable: list[str] | None = None):
    """Build a small in-memory rule set for focused tests."""
    full = []
    for i, r in enumerate(rules):
        full.append(
            {
                "id": r.get("id", f"TS-{i + 1:03d}"),
                "name": r.get("name", "test rule"),
                "category": r.get("category", "INSTRUCTION_OVERRIDE"),
                "severity": r.get("severity", "high"),
                "enabled": r.get("enabled", True),
                "description": r.get("description", "rule used in tests"),
                "patterns": r["patterns"],
            }
        )
    return parse_ruleset({"version": "test", "ignorable_tokens": ignorable or [], "rules": full})
