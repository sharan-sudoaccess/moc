"""Risk scoring and policy evaluation (application logic AROUND the DFA).

The DFA only answers "which configured patterns occur, and where?". Turning
that into a number and an action is a separate, configurable policy layer.
None of the numbers below are scientifically validated; they are an
explicit, explainable example configuration (config/policies.json).

Scoring formula
---------------
Each severity has a weight w in (0, 1):  low 0.15, medium 0.35, high 0.60,
critical 0.85 (configurable).

1. Duplicates are collapsed: a rule counts once, however often it matches.
2. Within a category only the strongest rule counts:
       w_c = max{ w(severity(r)) : r matched and category(r) = c }
   so ten variants of "ignore previous instructions" add nothing beyond
   the first.
3. Categories are combined with a "noisy-OR":
       score = 100 * (1 - Π_c (1 - w_c))
   Each additional, *independent* category raises the score, but the
   score can never exceed 100 and grows with diminishing returns
   (no uncontrolled inflation).

Example: override (high, 0.60) + extraction (high, 0.60)
       = 100 * (1 - 0.4 * 0.4) = 84.0

Risk level (configurable bands): NONE when score = 0, otherwise the
highest band whose minimum is <= score (LOW 0, MEDIUM 30, HIGH 60,
CRITICAL 85).

Policy decision
---------------
    no matches                                  -> ALLOW
    score >= block_threshold, or any matched
      rule's severity in block_on_severities    -> BLOCK
    score >= flag_threshold                     -> FLAG
    otherwise                                   -> ALLOW (matched, below flag threshold)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from src.detector import Match
from src.rules import CATEGORY_LABELS, SEVERITY_RANK, Severity


class Action(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class PolicyConfigError(ValueError):
    pass


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str
    flag_threshold: float = Field(ge=0, le=100)
    block_threshold: float | None = Field(default=None, ge=0, le=100)
    block_on_severities: tuple[Severity, ...] = ()

    @model_validator(mode="after")
    def _ordered(self) -> "PolicyModel":
        if self.block_threshold is not None and self.block_threshold < self.flag_threshold:
            raise ValueError("block_threshold must be >= flag_threshold")
        return self


class RiskBand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(pattern=r"^[A-Z]+$")
    min_score: float = Field(ge=0, le=100)


class ScoringConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity_weights: dict[Severity, float]
    risk_levels: tuple[RiskBand, ...] = Field(min_length=1)
    default_policy: str
    policies: dict[str, PolicyModel] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> "ScoringConfigModel":
        missing = [s.value for s in Severity if s not in self.severity_weights]
        if missing:
            raise ValueError(f"severity_weights missing: {missing}")
        for sev, w in self.severity_weights.items():
            if not 0 < w < 1:
                raise ValueError(f"weight for {sev.value} must be in (0, 1)")
        mins = [b.min_score for b in self.risk_levels]
        if mins != sorted(mins) or mins[0] != 0:
            raise ValueError("risk_levels must be sorted by min_score and start at 0")
        if self.default_policy not in self.policies:
            raise ValueError(f"default_policy {self.default_policy!r} is not defined")
        return self


ScoringConfig = ScoringConfigModel


def load_scoring_config(path: Path) -> ScoringConfig:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return ScoringConfigModel.model_validate(raw)
    except FileNotFoundError:
        raise PolicyConfigError(f"policy file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise PolicyConfigError(f"policy file is not valid JSON: {exc.msg}") from None
    except ValidationError as exc:
        raise PolicyConfigError(f"invalid policy configuration: {exc.errors()[0]['msg']}") from None


@dataclass(frozen=True)
class CategoryContribution:
    category: str
    category_label: str
    rule_id: str
    severity: str
    weight: float


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: str
    contributions: tuple[CategoryContribution, ...]
    total_matches: int
    distinct_rules: int
    duplicate_matches: int
    max_severity: str | None
    formula: str


def compute_risk(matches: Sequence[Match], config: ScoringConfig) -> RiskAssessment:
    weights = config.severity_weights
    distinct: dict[str, Match] = {}
    for m in matches:
        distinct.setdefault(m.rule_id, m)

    best: dict[str, CategoryContribution] = {}
    for m in distinct.values():
        w = weights[m.severity]
        current = best.get(m.category.value)
        # Strongest rule per category; ties broken by rule id for determinism.
        if current is None or (-w, m.rule_id) < (-current.weight, current.rule_id):
            best[m.category.value] = CategoryContribution(
                category=m.category.value,
                category_label=CATEGORY_LABELS[m.category],
                rule_id=m.rule_id,
                severity=m.severity.value,
                weight=w,
            )
    contributions = tuple(sorted(best.values(), key=lambda c: (-c.weight, c.category)))

    remaining = 1.0
    for c in contributions:
        remaining *= 1.0 - c.weight
    score = round(100.0 * (1.0 - remaining), 1) if contributions else 0.0

    if score == 0:
        level = "NONE"
    else:
        level = config.risk_levels[0].name
        for band in config.risk_levels:
            if score >= band.min_score:
                level = band.name

    max_sev = None
    if distinct:
        max_sev = max((m.severity for m in distinct.values()), key=lambda s: SEVERITY_RANK[s]).value

    terms = " × ".join(f"(1 − {c.weight:.2f})" for c in contributions) or "1"
    formula = f"100 × (1 − {terms}) = {score}"

    return RiskAssessment(
        score=score,
        level=level,
        contributions=contributions,
        total_matches=len(matches),
        distinct_rules=len(distinct),
        duplicate_matches=len(matches) - len(distinct),
        max_severity=max_sev,
        formula=formula,
    )


@dataclass(frozen=True)
class Decision:
    action: Action
    policy: str
    reasons: tuple[str, ...]


def decide(
    risk: RiskAssessment, matches: Sequence[Match], policy_name: str, config: ScoringConfig
) -> Decision:
    if policy_name not in config.policies:
        raise KeyError(policy_name)
    policy = config.policies[policy_name]
    if not matches:
        return Decision(Action.ALLOW, policy_name, ("No configured detection rule matched.",))

    reasons: list[str] = []
    block_sevs = set(policy.block_on_severities)
    severity_hits = sorted({m.rule_id for m in matches if m.severity in block_sevs})
    if severity_hits:
        sev_names = ", ".join(sorted({s.value for s in block_sevs}))
        reasons.append(
            f"Policy '{policy_name}' blocks any match of severity [{sev_names}]: "
            f"triggered by {', '.join(severity_hits)}."
        )
    if policy.block_threshold is not None and risk.score >= policy.block_threshold:
        reasons.append(
            f"Risk score {risk.score} >= block threshold {policy.block_threshold:g} "
            f"of policy '{policy_name}'."
        )
    if reasons:
        return Decision(Action.BLOCK, policy_name, tuple(reasons))

    if risk.score >= policy.flag_threshold:
        return Decision(
            Action.FLAG,
            policy_name,
            (
                f"Risk score {risk.score} >= flag threshold {policy.flag_threshold:g} "
                f"of policy '{policy_name}'; human review recommended.",
            ),
        )
    return Decision(
        Action.ALLOW,
        policy_name,
        (
            f"Rules matched, but risk score {risk.score} is below the flag threshold "
            f"{policy.flag_threshold:g} of policy '{policy_name}'.",
        ),
    )
