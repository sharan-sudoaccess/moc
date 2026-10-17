"""Thin HTTP client for the detection API (the dashboard's only data source)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests


class ApiError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


@dataclass
class ApiClient:
    base_url: str
    api_key: str | None = None
    timeout: float = 15.0

    @classmethod
    def from_env(cls) -> "ApiClient":
        return cls(
            base_url=os.environ.get("API_URL", "http://127.0.0.1:8000").rstrip("/"),
            api_key=os.environ.get("API_KEY") or None,
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = kwargs.pop("headers", {})
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            resp = requests.request(method, f"{self.base_url}{path}", headers=headers,
                                    timeout=self.timeout, **kwargs)
        except requests.ConnectionError:
            raise ApiError(f"Cannot reach the API at {self.base_url}. Is it running?") from None
        except requests.Timeout:
            raise ApiError(f"The API at {self.base_url} did not respond within {self.timeout:.0f}s.") from None
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code >= 400:
            err = (body or {}).get("error", {}) if isinstance(body, dict) else {}
            message = err.get("message") or f"HTTP {resp.status_code}"
            details = err.get("details")
            if details:
                message += " — " + "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in details[:4])
            raise ApiError(message, resp.status_code, err.get("code"))
        return body

    # Status
    def health(self) -> dict:
        return self._request("GET", "/health")

    def ready(self) -> dict:
        # /ready returns 503 with a JSON body when not ready; surface the body either way.
        try:
            resp = requests.get(f"{self.base_url}/ready", timeout=self.timeout)
        except requests.RequestException:
            raise ApiError(f"Cannot reach the API at {self.base_url}.") from None
        return resp.json()

    def metrics(self) -> dict:
        return self._request("GET", "/v1/metrics")

    # Detection
    def detect(self, text: str, policy: str | None = None, include_trace: bool = False) -> dict:
        payload: dict[str, Any] = {"text": text, "include_trace": include_trace}
        if policy:
            payload["policy"] = policy
        return self._request("POST", "/v1/detect", json=payload)

    # Rules / policies / automaton
    def patterns(self) -> dict:
        return self._request("GET", "/v1/patterns")

    def toggle_rule(self, rule_id: str, enabled: bool) -> dict:
        return self._request("PATCH", f"/v1/patterns/{rule_id}", json={"enabled": enabled})

    def add_rule(self, rule: dict) -> dict:
        return self._request("POST", "/v1/patterns", json=rule)

    def policies(self) -> dict:
        return self._request("GET", "/v1/policies")

    def automaton(self) -> dict:
        return self._request("GET", "/v1/automaton")

    def state(self, q: int) -> dict:
        return self._request("GET", f"/v1/automaton/states/{q}")

    def evaluation(self, split: str, policy: str | None, positive_on: str) -> dict:
        params = {"split": split, "positive_on": positive_on}
        if policy:
            params["policy"] = policy
        return self._request("GET", "/v1/evaluation", params=params)
