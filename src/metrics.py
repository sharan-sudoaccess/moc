"""In-memory metrics and a sliding-window rate limiter.

Both live in process memory. Consequences (documented in docs/limitations.md):
* counters reset when the API restarts;
* with several worker processes, each worker has its own counters and its
  own rate-limit window, so the effective limit is multiplied;
* the recent-scan buffer holds metadata only (no input text).
"""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from typing import Any


class MetricsRegistry:
    def __init__(self, recent_size: int = 100) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.requests_total = 0
        self.requests_by_status: Counter[str] = Counter()
        self.requests_by_path: Counter[str] = Counter()
        self.scans_total = 0
        self.scans_with_matches = 0
        self.actions: Counter[str] = Counter()
        self.risk_levels: Counter[str] = Counter()
        self.categories: Counter[str] = Counter()
        self.rule_hits: Counter[str] = Counter()
        self.latency_total_ms = 0.0
        self.latency_max_ms = 0.0
        self.tokens_total = 0
        self.recent: deque[dict[str, Any]] = deque(maxlen=recent_size)

    def record_request(self, path: str, status: int) -> None:
        with self._lock:
            self.requests_total += 1
            self.requests_by_status[str(status)] += 1
            self.requests_by_path[path] += 1

    def record_scan(self, summary: dict[str, Any]) -> None:
        with self._lock:
            self.scans_total += 1
            if summary["rule_ids"]:
                self.scans_with_matches += 1
            self.actions[summary["action"]] += 1
            self.risk_levels[summary["risk_level"]] += 1
            self.categories.update(summary["categories"])
            self.rule_hits.update(summary["rule_ids"])
            self.latency_total_ms += summary["processing_ms"]
            self.latency_max_ms = max(self.latency_max_ms, summary["processing_ms"])
            self.tokens_total += summary["token_count"]
            self.recent.appendleft(dict(summary))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            scans = self.scans_total
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "requests_total": self.requests_total,
                "requests_by_status": dict(self.requests_by_status),
                "requests_by_path": dict(self.requests_by_path),
                "scans_total": scans,
                "scans_with_matches": self.scans_with_matches,
                "detection_rate": round(self.scans_with_matches / scans, 4) if scans else 0.0,
                "actions": {a: self.actions.get(a, 0) for a in ("ALLOW", "FLAG", "BLOCK")},
                "risk_levels": {
                    lvl: self.risk_levels.get(lvl, 0)
                    for lvl in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
                },
                "categories": dict(self.categories.most_common()),
                "rule_hits": dict(self.rule_hits.most_common()),
                "avg_latency_ms": round(self.latency_total_ms / scans, 3) if scans else 0.0,
                "max_latency_ms": round(self.latency_max_ms, 3),
                "avg_tokens_per_scan": round(self.tokens_total / scans, 1) if scans else 0.0,
                "recent_scans": list(self.recent),
                "storage": "in-memory (resets on restart, per process)",
            }


class RateLimiter:
    """Sliding-window limiter: at most ``limit`` requests per ``window`` seconds per key."""

    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 10_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        if not self.enabled:
            return True, 0
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._evict(now)
                hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                retry = int(self.window - (now - hits[0])) + 1
                return False, max(retry, 1)
            hits.append(now)
            return True, 0

    def _evict(self, now: float) -> None:
        stale = [k for k, h in self._hits.items() if not h or now - h[-1] >= self.window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) >= self.max_keys:  # still full: drop the oldest keys
            for k in sorted(self._hits, key=lambda k: self._hits[k][-1])[: self.max_keys // 10]:
                del self._hits[k]
