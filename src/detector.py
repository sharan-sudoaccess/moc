"""Compiles the rule set into the DFA and turns raw automaton matches into evidence.

This module is the bridge between the formal recognizer (automaton.py) and
the security application. It:

1. collects the canonical token sequences of every ENABLED rule,
2. builds one :class:`TokenAutomaton` recognizing all of them at once,
3. runs normalized input through it, and
4. maps each automaton match back to its rule, category, severity and the
   exact span of the ORIGINAL text that produced it (the evidence).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.automaton import RunResult, TokenAutomaton, TraceStep
from src.normalization import NormalizedText, find_quoted_spans, normalize_text
from src.rules import Category, Rule, RuleSet, Severity


@dataclass(frozen=True)
class CompiledPattern:
    pattern_id: int
    rule_id: str
    source: str
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    rule_id: str
    rule_name: str
    category: Category
    severity: Severity
    description: str
    pattern: str  # canonical form that the DFA recognized
    pattern_source: str  # pattern as written in the configuration
    matched_text: str  # slice of the ORIGINAL input (evidence)
    start_char: int
    end_char: int
    start_token: int
    end_token: int
    accepting_state: int
    in_quotes: bool


@dataclass(frozen=True)
class ScanResult:
    normalized: NormalizedText
    run: RunResult
    matches: tuple[Match, ...]

    @property
    def trace(self) -> tuple[TraceStep, ...]:
        return self.run.trace


class PromptInjectionDetector:
    """Rule set + compiled automaton. Immutable; rebuild to change rules."""

    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset
        self._rules: dict[str, Rule] = {r.id: r for r in ruleset.rules}
        compiled: list[CompiledPattern] = []
        for rule in ruleset.rules:
            if not rule.enabled:
                continue
            canonical_forms = ruleset.canonical[rule.id]
            for source, tokens in zip(rule.patterns, canonical_forms):
                compiled.append(CompiledPattern(len(compiled), rule.id, source, tokens))
        self.patterns: tuple[CompiledPattern, ...] = tuple(compiled)
        self.automaton = TokenAutomaton(
            [p.tokens for p in compiled], skip_tokens=ruleset.ignorable_tokens
        )

    def scan(
        self,
        text: str,
        normalized: NormalizedText | None = None,
        *,
        include_trace: bool = False,
        max_trace_steps: int | None = None,
    ) -> ScanResult:
        """Run the DFA over ``text``. ``text`` must already be validated."""
        if normalized is None:
            normalized = normalize_text(text)
        run = self.automaton.run(
            normalized.token_texts, trace=include_trace, max_trace_steps=max_trace_steps
        )
        quoted = find_quoted_spans(text) if run.matches else []
        tokens = normalized.tokens
        matches: list[Match] = []
        for am in run.matches:
            cp = self.patterns[am.pattern_id]
            rule = self._rules[cp.rule_id]
            start_char = tokens[am.start_pos].start
            end_char = tokens[am.end_pos].end
            matches.append(
                Match(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    pattern=" ".join(cp.tokens),
                    pattern_source=cp.source,
                    matched_text=text[start_char:end_char],
                    start_char=start_char,
                    end_char=end_char,
                    start_token=am.start_pos,
                    end_token=am.end_pos,
                    accepting_state=am.state,
                    in_quotes=any(qs <= start_char and end_char <= qe for qs, qe in quoted),
                )
            )
        return ScanResult(normalized=normalized, run=run, matches=tuple(matches))

    def pattern_info(self, pattern_id: int) -> CompiledPattern:
        return self.patterns[pattern_id]

    def describe(self) -> dict:
        info = self.automaton.describe()
        info["enabled_rules"] = len(self.ruleset.enabled_rules)
        info["total_rules"] = len(self.ruleset.rules)
        return info
