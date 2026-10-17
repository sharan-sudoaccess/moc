"""Structured, privacy-preserving audit log (JSON Lines with size-based rotation).

What is written (one JSON object per line, per scan):
    timestamp, event, request_id, detector_version, ruleset_version,
    ruleset_fingerprint, policy, decision, risk_score, risk_level,
    rule_ids, categories, match_count, token_count, input_chars,
    processing_ms, input_sha256 / input_hmac_sha256 (optional),
    client_ip (optional, off by default)

What is NOT written by default: the raw input text. Writing it requires
the explicit opt-in AUDIT_LOG_RAW_INPUT=true.

Input hashing: a plain SHA-256 lets you correlate repeated submissions
without storing them, but it is NOT anonymization: short or predictable
inputs ("ignore previous instructions") can be recovered by hashing
guesses. Setting AUDIT_HASH_KEY switches to a keyed HMAC-SHA256, which
prevents offline guessing by anyone who has the log but not the key.

Log growth is bounded by ``RotatingFileHandler``: at most
``(backup_count + 1) * max_bytes`` bytes on disk. This file is NOT
tamper-evident: anyone with write access to logs/ can edit or delete it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = 5_000_000,
        backup_count: int = 5,
        hash_input: bool = True,
        hash_key: str | None = None,
        log_raw_input: bool = False,
    ) -> None:
        self.path = Path(path)
        self.hash_input = hash_input
        self._hash_key = hash_key.encode("utf-8") if hash_key else None
        self.log_raw_input = log_raw_input
        self._lock = threading.Lock()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A dedicated, non-propagating logger per file so audit records never
        # leak into the application log (and vice versa).
        self._logger = logging.getLogger(f"audit.{self.path.resolve()}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for handler in list(self._logger.handlers):
            self._logger.removeHandler(handler)
            handler.close()
        self._handler = RotatingFileHandler(
            self.path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._handler)
        try:
            os.chmod(self.path, 0o640)
        except OSError:
            pass

    def fingerprint(self, text: str) -> dict[str, str]:
        if not self.hash_input:
            return {}
        data = text.encode("utf-8")
        if self._hash_key:
            return {"input_hmac_sha256": hmac.new(self._hash_key, data, hashlib.sha256).hexdigest()}
        return {"input_sha256": hashlib.sha256(data).hexdigest()}

    def record(self, event: dict[str, Any], *, raw_text: str | None = None) -> None:
        entry = dict(event)
        if raw_text is not None:
            entry.update(self.fingerprint(raw_text))
            if self.log_raw_input:
                entry["raw_input"] = raw_text
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._logger.info(line)

    def is_writable(self) -> bool:
        return os.access(self.path.parent, os.W_OK) and (
            not self.path.exists() or os.access(self.path, os.W_OK)
        )

    def close(self) -> None:
        self._logger.removeHandler(self._handler)
        self._handler.close()
