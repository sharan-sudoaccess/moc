"""Detection-rule configuration: loading, validation, canonicalization, saving.

Rules live in ``config/patterns.json``. Each rule groups one or more
*patterns* (phrase variants) under a single ID, category and severity.

A pattern is written in plain English. It is canonicalized with exactly the
same normalization + tokenization pipeline used for user input, and the
configured ignorable tokens are removed. The resulting token sequence is
what the automaton learns. For example, with "the" and "your" ignorable,
"Reveal the system prompt" and "reveal your system prompt" both become
("reveal", "system", "prompt").

Validation is strict and fails loudly: a bad configuration is never
half-loaded. Problems detected:

* malformed JSON / missing fields / wrong types / unknown fields
* unknown category or severity, malformed rule IDs
* duplicate rule IDs
* a pattern that is empty after canonicalization (e.g. only filler words)
* a pattern longer than ``MAX_PATTERN_TOKENS``
* two patterns (in any rules, enabled or not) with the same canonical form
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from enum import Enum
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.normalization import tokenize

MAX_PATTERN_TOKENS = 12
MAX_PATTERNS_PER_RULE = 64


class Category(str, Enum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    ROLE_MANIPULATION = "ROLE_MANIPULATION"
    SAFETY_BYPASS = "SAFETY_BYPASS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIORITY_MANIPULATION = "PRIORITY_MANIPULATION"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"


CATEGORY_LABELS = {
    Category.INSTRUCTION_OVERRIDE: "Instruction override",
    Category.SYSTEM_PROMPT_EXTRACTION: "System prompt extraction",
    Category.ROLE_MANIPULATION: "Role manipulation",
    Category.SAFETY_BYPASS: "Safety bypass",
    Category.DATA_EXFILTRATION: "Data exfiltration",
    Category.PRIORITY_MANIPULATION: "Instruction priority manipulation",
    Category.INDIRECT_INJECTION: "Indirect / embedded instruction",
}


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class RuleConfigError(ValueError):
    """The rule configuration is invalid. ``problems`` lists every issue found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("Invalid rule configuration: " + "; ".join(problems))


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Z]{2,5}-\d{3}$")
    name: str = Field(min_length=3, max_length=80)
    category: Category
    severity: Severity
    enabled: bool = True
    description: str = Field(min_length=5, max_length=500)
    patterns: tuple[str, ...] = Field(min_length=1, max_length=MAX_PATTERNS_PER_RULE)

    @field_validator("patterns")
    @classmethod
    def _patterns_not_blank(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for p in value:
            if not isinstance(p, str) or not p.strip():
                raise ValueError("patterns must be non-empty strings")
            if len(p) > 200:
                raise ValueError("a pattern may not exceed 200 characters")
        return value


class RuleSetFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1, max_length=40)
    description: str = ""
    ignorable_tokens: tuple[str, ...] = ()
    rules: tuple[Rule, ...]


def canonical_tokens(pattern: str, ignorable: Iterable[str]) -> tuple[str, ...]:
    """Normalize and tokenize a pattern, then drop ignorable tokens."""
    skip = set(ignorable)
    return tuple(t for t in tokenize(pattern) if t not in skip)


class RuleSet:
    """A validated rule configuration plus its canonical pattern forms."""

    def __init__(self, data: RuleSetFile) -> None:
        self.data = data
        problems: list[str] = []

        ignorable: list[str] = []
        for raw in data.ignorable_tokens:
            toks = tokenize(raw)
            if len(toks) != 1:
                problems.append(f"ignorable token {raw!r} must normalize to exactly one token")
            else:
                ignorable.append(toks[0])
        self.ignorable_tokens: tuple[str, ...] = tuple(sorted(set(ignorable)))

        seen_ids: set[str] = set()
        seen_patterns: dict[tuple[str, ...], str] = {}
        self.canonical: dict[str, tuple[tuple[str, ...], ...]] = {}
        for rule in data.rules:
            if rule.id in seen_ids:
                problems.append(f"duplicate rule id {rule.id}")
                continue
            seen_ids.add(rule.id)
            forms: list[tuple[str, ...]] = []
            for pattern in rule.patterns:
                toks = canonical_tokens(pattern, self.ignorable_tokens)
                if not toks:
                    problems.append(
                        f"{rule.id}: pattern {pattern!r} is empty after normalization "
                        "(it contains only ignorable tokens or punctuation)"
                    )
                    continue
                if len(toks) > MAX_PATTERN_TOKENS:
                    problems.append(
                        f"{rule.id}: pattern {pattern!r} has {len(toks)} tokens "
                        f"(max {MAX_PATTERN_TOKENS})"
                    )
                    continue
                if toks in seen_patterns:
                    problems.append(
                        f"{rule.id}: pattern {pattern!r} has the same canonical form "
                        f"{' '.join(toks)!r} as a pattern in {seen_patterns[toks]}"
                    )
                    continue
                seen_patterns[toks] = rule.id
                forms.append(toks)
            self.canonical[rule.id] = tuple(forms)

        if problems:
            raise RuleConfigError(problems)

    # ---------------------------------------------------------------- access
    @property
    def version(self) -> str:
        return self.data.version

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self.data.rules

    @property
    def enabled_rules(self) -> tuple[Rule, ...]:
        return tuple(r for r in self.data.rules if r.enabled)

    def get(self, rule_id: str) -> Rule | None:
        return next((r for r in self.data.rules if r.id == rule_id), None)

    def to_dict(self) -> dict:
        return self.data.model_dump(mode="json")

    @property
    def fingerprint(self) -> str:
        """SHA-256 over the canonical JSON form; identifies the exact rule set."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    # -------------------------------------------------------------- mutation
    def with_rule_enabled(self, rule_id: str, enabled: bool) -> "RuleSet":
        if self.get(rule_id) is None:
            raise KeyError(rule_id)
        rules = tuple(
            r.model_copy(update={"enabled": enabled}) if r.id == rule_id else r for r in self.rules
        )
        return RuleSet(self.data.model_copy(update={"rules": rules}))

    def with_added_rule(self, rule: Rule) -> "RuleSet":
        if self.get(rule.id) is not None:
            raise RuleConfigError([f"rule id {rule.id} already exists"])
        return RuleSet(self.data.model_copy(update={"rules": self.rules + (rule,)}))


def parse_ruleset(raw: object) -> RuleSet:
    try:
        data = RuleSetFile.model_validate(raw)
    except ValidationError as exc:
        problems = [
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()
        ]
        raise RuleConfigError(problems) from None
    return RuleSet(data)


def load_ruleset(path: Path) -> RuleSet:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleConfigError([f"rule file not found: {path}"]) from None
    except json.JSONDecodeError as exc:
        raise RuleConfigError([f"rule file is not valid JSON: {exc.msg} (line {exc.lineno})"]) from None
    return parse_ruleset(raw)


def save_ruleset_atomic(ruleset: RuleSet, path: Path) -> None:
    """Write the rule file atomically: write a temp file, fsync, then rename.

    A crash mid-write therefore leaves either the old or the new file, never
    a truncated one.
    """
    path = Path(path)
    payload = json.dumps(ruleset.to_dict(), indent=2, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".patterns-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
