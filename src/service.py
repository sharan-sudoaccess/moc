"""DetectionService: the full pipeline in one place.

    validate -> normalize/tokenize -> DFA scan -> score -> policy -> audit/metrics -> response

The FastAPI layer (api.py) and the evaluation script both call this class,
so the dashboard, the API and the evaluation always exercise the SAME code.

Rule changes are applied copy-on-write: a new RuleSet is validated, a new
detector (automaton) is compiled, the file is written atomically, and only
then is the live detector swapped under a lock. If any step fails the old
detector keeps serving and the error is returned to the caller.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from src.config import DETECTOR_VERSION, Settings
from src.audit import AuditLogger
from src.detector import Match, PromptInjectionDetector
from src.metrics import MetricsRegistry
from src.normalization import normalize_text, validate_input
from src.rules import (
    CATEGORY_LABELS,
    Rule,
    RuleConfigError,
    RuleSet,
    load_ruleset,
    save_ruleset_atomic,
)
from src.scoring import Action, ScoringConfig, compute_risk, decide, load_scoring_config


class UnknownPolicyError(KeyError):
    pass


class RuleEditingDisabledError(PermissionError):
    pass


def _ms(seconds: float) -> float:
    return round(seconds * 1000.0, 3)


def _summary(action: Action, matches: list[Match], risk_level: str) -> str:
    if not matches:
        return "No configured prompt-injection pattern was recognized."
    cats = sorted({CATEGORY_LABELS[m.category] for m in matches})
    rules = sorted({m.rule_id for m in matches})
    return (
        f"{action.value}: {len(rules)} rule(s) matched ({', '.join(rules)}) across "
        f"{len(cats)} categor{'y' if len(cats) == 1 else 'ies'} ({'; '.join(cats)}). "
        f"Risk level {risk_level}."
    )


class DetectionService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self._lock = threading.RLock()
        ruleset = load_ruleset(self.settings.patterns_path)
        self._detector = PromptInjectionDetector(ruleset)
        self.scoring: ScoringConfig = load_scoring_config(self.settings.policies_path)
        self.audit = AuditLogger(
            self.settings.audit_log_path,
            max_bytes=self.settings.audit_max_bytes,
            backup_count=self.settings.audit_backup_count,
            hash_input=self.settings.audit_hash_input,
            hash_key=self.settings.audit_hash_key,
            log_raw_input=self.settings.audit_log_raw_input,
        )
        self.metrics = MetricsRegistry()
        self.started_at = time.time()

    # ------------------------------------------------------------- accessors
    @property
    def detector(self) -> PromptInjectionDetector:
        with self._lock:
            return self._detector

    @property
    def default_policy(self) -> str:
        return self.scoring.default_policy

    def resolve_policy(self, name: str | None) -> str:
        policy = name or self.scoring.default_policy
        if policy not in self.scoring.policies:
            raise UnknownPolicyError(policy)
        return policy

    # -------------------------------------------------------------- analyze
    def analyze(
        self,
        text: object,
        *,
        policy: str | None = None,
        include_trace: bool = False,
        request_id: str | None = None,
        client_ip: str | None = None,
        record: bool = True,
    ) -> dict[str, Any]:
        """Run the complete pipeline and return a DetectResponse-shaped dict.

        Raises InputValidationError for bad input and UnknownPolicyError for
        an unknown policy name.
        """
        t_start = time.perf_counter()
        request_id = request_id or str(uuid.uuid4())
        policy_name = self.resolve_policy(policy)

        validated = validate_input(text, self.settings.max_input_chars)
        t_valid = time.perf_counter()

        normalized = normalize_text(validated)
        t_norm = time.perf_counter()

        detector = self.detector  # snapshot: a concurrent rule change cannot affect this scan
        scan = detector.scan(
            validated,
            normalized,
            include_trace=include_trace,
            max_trace_steps=self.settings.max_trace_steps,
        )
        t_scan = time.perf_counter()

        matches = list(scan.matches)
        risk = compute_risk(matches, self.scoring)
        decision = decide(risk, matches, policy_name, self.scoring)
        t_policy = time.perf_counter()

        automaton = detector.automaton
        rule_ids = sorted({m.rule_id for m in matches})
        categories = sorted({m.category.value for m in matches})
        skipped = sum(1 for t in normalized.tokens if t.text in automaton.skip_tokens)

        explanations = []
        seen_rules: set[str] = set()
        for m in matches:
            if m.rule_id in seen_rules:
                continue
            seen_rules.add(m.rule_id)
            note = " Inside quotation marks: this may be a mention rather than an instruction." if m.in_quotes else ""
            explanations.append(
                f"{m.rule_id} [{CATEGORY_LABELS[m.category]}, {m.severity.value}] "
                f"recognized pattern '{m.pattern}' as \"{m.matched_text}\" "
                f"(chars {m.start_char}-{m.end_char}, accepting state q{m.accepting_state}). "
                f"{m.description}{note}"
            )
        dups = risk.duplicate_matches
        if dups:
            explanations.append(
                f"{dups} additional match(es) of already-matched rules were counted once (no score inflation)."
            )

        result: dict[str, Any] = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "detector_version": DETECTOR_VERSION,
            "ruleset_version": detector.ruleset.version,
            "ruleset_fingerprint": detector.ruleset.fingerprint,
            "policy": policy_name,
            "detected": bool(matches),
            "action": decision.action.value,
            "risk_score": risk.score,
            "risk_level": risk.level,
            "max_severity": risk.max_severity,
            "summary": _summary(decision.action, matches, risk.level),
            "rule_ids": rule_ids,
            "categories": categories,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "category": m.category.value,
                    "category_label": CATEGORY_LABELS[m.category],
                    "severity": m.severity.value,
                    "description": m.description,
                    "pattern": m.pattern,
                    "pattern_source": m.pattern_source,
                    "matched_text": m.matched_text,
                    "start_char": m.start_char,
                    "end_char": m.end_char,
                    "start_token": m.start_token,
                    "end_token": m.end_token,
                    "accepting_state": m.accepting_state,
                    "in_quotes": m.in_quotes,
                }
                for m in matches
            ],
            "explanations": explanations,
            "decision_reasons": list(decision.reasons),
            "score_breakdown": {
                "formula": risk.formula,
                "contributions": [c.__dict__ for c in risk.contributions],
                "total_matches": risk.total_matches,
                "distinct_rules": risk.distinct_rules,
                "duplicate_matches": risk.duplicate_matches,
            },
            "input_chars": len(validated),
            "token_count": len(normalized.tokens),
            "normalization": {
                "canonical_text": normalized.canonical,
                "zero_width_removed": normalized.stats.zero_width_removed,
                "diacritics_removed": normalized.stats.diacritics_removed,
                "confusables_mapped": normalized.stats.confusables_mapped,
                "compatibility_changes": normalized.stats.compatibility_changes,
                "obfuscation_signals": normalized.stats.obfuscation_signals,
            },
            "automaton": {
                "num_states": automaton.num_states,
                "alphabet_size": len(automaton.alphabet),
                "final_state": scan.run.final_state,
                "states_visited": scan.run.states_visited,
                "symbols_consumed": len(normalized.tokens) - skipped,
                "skipped_tokens": skipped,
            },
            "tokens": None,
            "trace": None,
            "trace_truncated": scan.run.trace_truncated,
        }

        if include_trace:
            result["tokens"] = [
                {
                    "index": t.index,
                    "text": t.text,
                    "symbol": automaton.symbol_name(automaton.symbol_of(t.text)),
                    "start": t.start,
                    "end": t.end,
                }
                for t in normalized.tokens
            ]
            result["trace"] = [
                {
                    "step": s.step,
                    "position": s.position,
                    "token": s.token,
                    "symbol": s.symbol,
                    "from_state": s.from_state,
                    "to_state": s.to_state,
                    "to_label": automaton.state_label(s.to_state),
                    "transition": s.transition,
                    "accepting": s.to_state in automaton.accepting,
                    "outputs": [detector.pattern_info(pid).rule_id for pid in s.outputs],
                }
                for s in scan.trace
            ]

        t_end = time.perf_counter()
        result["timings_ms"] = {
            "validation": _ms(t_valid - t_start),
            "normalization": _ms(t_norm - t_valid),
            "dfa_scan": _ms(t_scan - t_norm),
            "scoring_policy": _ms(t_policy - t_scan),
            "report": _ms(t_end - t_policy),
        }
        result["processing_ms"] = _ms(t_end - t_start)

        if record:
            audit_event = {
                "event": "detection",
                "timestamp": result["timestamp"],
                "request_id": request_id,
                "detector_version": DETECTOR_VERSION,
                "ruleset_version": result["ruleset_version"],
                "ruleset_fingerprint": result["ruleset_fingerprint"],
                "policy": policy_name,
                "decision": result["action"],
                "risk_score": risk.score,
                "risk_level": risk.level,
                "rule_ids": rule_ids,
                "categories": categories,
                "match_count": len(matches),
                "token_count": result["token_count"],
                "input_chars": result["input_chars"],
                "processing_ms": result["processing_ms"],
            }
            if client_ip and self.settings.audit_log_client_ip:
                audit_event["client_ip"] = client_ip
            self.audit.record(audit_event, raw_text=validated)
            self.metrics.record_scan(
                {
                    "request_id": request_id,
                    "timestamp": result["timestamp"],
                    "policy": policy_name,
                    "action": result["action"],
                    "risk_score": risk.score,
                    "risk_level": risk.level,
                    "rule_ids": rule_ids,
                    "categories": categories,
                    "token_count": result["token_count"],
                    "processing_ms": result["processing_ms"],
                }
            )
        return result

    # ----------------------------------------------------------------- rules
    def rules_report(self) -> dict[str, Any]:
        ruleset = self.detector.ruleset
        rules = []
        for r in ruleset.rules:
            rules.append(
                {
                    "id": r.id,
                    "name": r.name,
                    "category": r.category.value,
                    "category_label": CATEGORY_LABELS[r.category],
                    "severity": r.severity.value,
                    "enabled": r.enabled,
                    "description": r.description,
                    "patterns": list(r.patterns),
                    "canonical_patterns": [" ".join(t) for t in ruleset.canonical[r.id]],
                }
            )
        return {
            "ruleset_version": ruleset.version,
            "ruleset_fingerprint": ruleset.fingerprint,
            "ignorable_tokens": list(ruleset.ignorable_tokens),
            "total_rules": len(ruleset.rules),
            "enabled_rules": len(ruleset.enabled_rules),
            "total_patterns": sum(len(r.patterns) for r in ruleset.rules),
            "rule_editing_enabled": self.settings.rule_editing_enabled,
            "rules": rules,
        }

    def _apply_ruleset(self, new_ruleset: RuleSet, change: dict[str, Any]) -> None:
        """Compile, persist and swap. The old detector stays live on any failure."""
        new_detector = PromptInjectionDetector(new_ruleset)  # may raise AutomatonBuildError
        with self._lock:
            save_ruleset_atomic(new_ruleset, self.settings.patterns_path)
            old = self._detector.ruleset.fingerprint
            self._detector = new_detector
        self.audit.record(
            {
                "event": "ruleset_changed",
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "detector_version": DETECTOR_VERSION,
                "previous_fingerprint": old,
                "ruleset_fingerprint": new_ruleset.fingerprint,
                **change,
            }
        )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        if not self.settings.rule_editing_enabled:
            raise RuleEditingDisabledError("Rule editing is disabled (RULE_EDITING_ENABLED=false).")
        with self._lock:
            new_ruleset = self._detector.ruleset.with_rule_enabled(rule_id, enabled)  # KeyError if unknown
            self._apply_ruleset(new_ruleset, {"change": "toggle", "rule_id": rule_id, "enabled": enabled})
        return self.rules_report()

    def add_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        if not self.settings.rule_editing_enabled:
            raise RuleEditingDisabledError("Rule editing is disabled (RULE_EDITING_ENABLED=false).")
        try:
            rule = Rule.model_validate(rule_data)
        except Exception as exc:  # pydantic.ValidationError
            raise RuleConfigError([str(exc).splitlines()[0]]) from None
        with self._lock:
            new_ruleset = self._detector.ruleset.with_added_rule(rule)  # RuleConfigError on conflict
            self._apply_ruleset(new_ruleset, {"change": "add", "rule_id": rule.id})
        return self.rules_report()

    # ------------------------------------------------------------- automaton
    def automaton_report(self, include_states: bool = False) -> dict[str, Any]:
        detector = self.detector
        automaton = detector.automaton
        info = detector.describe()
        info["alphabet_preview"] = list(automaton.alphabet[:40])
        info["skip_symbol"] = automaton.alphabet[automaton.skip_symbol]
        info["other_symbol"] = automaton.alphabet[automaton.other_symbol]
        if include_states:
            info["states"] = [self.state_report(q, compact=True) for q in range(automaton.num_states)]
        return info

    def state_report(self, state: int, compact: bool = False) -> dict[str, Any]:
        detector = self.detector
        a = detector.automaton
        if not 0 <= state < a.num_states:
            raise IndexError(state)
        report = {
            "state": state,
            "label": a.state_label(state),
            "depth": len(a.labels[state]),
            "accepting": state in a.accepting,
            "failure_state": a.fail[state],
            "failure_label": a.state_label(a.fail[state]),
            "outputs": [
                {"rule_id": detector.pattern_info(pid).rule_id, "pattern": " ".join(a.patterns[pid])}
                for pid in a.output[state]
            ],
        }
        if not compact:
            report["transitions"] = [
                {"symbol": sym, "target": tgt, "target_label": a.state_label(tgt), "kind": kind}
                for sym, tgt, kind in sorted(
                    a.nontrivial_transitions(state),
                    key=lambda t: (t[2] != "trie", -len(a.labels[t[1]]), t[0]),
                )
            ]
            report["default_transitions"] = {
                a.alphabet[a.skip_symbol]: state,
                a.alphabet[a.other_symbol]: 0,
                "every other symbol": 0,
            }
        return report

    # ------------------------------------------------------------- readiness
    def readiness(self) -> dict[str, Any]:
        detector = self.detector
        checks = {
            "rules_loaded": len(detector.ruleset.rules) > 0,
            "rules_enabled": len(detector.ruleset.enabled_rules) > 0,
            "automaton_built": detector.automaton.num_states >= 1,
            "policies_loaded": len(self.scoring.policies) > 0,
            "audit_log_writable": self.audit.is_writable(),
        }
        return {
            "ready": all(checks.values()),
            "checks": checks,
            "detector_version": DETECTOR_VERSION,
            "ruleset_version": detector.ruleset.version,
            "ruleset_fingerprint": detector.ruleset.fingerprint,
            "enabled_rules": len(detector.ruleset.enabled_rules),
            "patterns_compiled": len(detector.patterns),
            "automaton_states": detector.automaton.num_states,
        }
