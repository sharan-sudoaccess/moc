"""FastAPI service exposing the detector.

Run:  uvicorn src.api:app --host 127.0.0.1 --port 8000

Endpoints
    GET   /health                      liveness (no auth)
    GET   /ready                       readiness: rules, automaton, policies, audit log (no auth)
    POST  /v1/detect                   analyze text
    GET   /v1/patterns                 configured rules
    PATCH /v1/patterns/{rule_id}       enable / disable a rule  (RULE_EDITING_ENABLED=true)
    POST  /v1/patterns                 add a rule               (RULE_EDITING_ENABLED=true)
    GET   /v1/policies                 scoring weights, risk bands and policies
    GET   /v1/automaton                automaton statistics (optionally every state)
    GET   /v1/automaton/states/{q}     one state: label, failure link, outputs, transitions
    GET   /v1/metrics                  in-memory request / detection metrics
    GET   /v1/evaluation               run the labeled corpus through the detector

Protections: optional API key (X-API-Key, from the API_KEY env var),
per-client sliding-window rate limit, request-size limit, input-length
limit, request IDs, security headers, configurable CORS, sanitized error
messages (validation errors never echo the submitted text).
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import sys
import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.automaton import AutomatonBuildError
from src.config import DETECTOR_VERSION, Settings
from src.evaluation import POSITIVE_MODES, SPLITS, CorpusError, evaluate, load_corpus
from src.metrics import RateLimiter
from src.models import (
    DetectRequest,
    DetectResponse,
    ErrorResponse,
    RuleCreateRequest,
    RulesResponse,
    RuleToggleRequest,
)
from src.normalization import InputValidationError
from src.rules import RuleConfigError
from src.service import DetectionService, RuleEditingDisabledError, UnknownPolicyError

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# Swagger UI / ReDoc load their JS and CSS from a CDN, so they get a looser CSP.
API_CSP = "default-src 'none'; frame-ancestors 'none'"
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect")


def _configure_app_logger() -> logging.Logger:
    logger = logging.getLogger("pidfa.api")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None,
                 details: list | None = None) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
        self.details = details


def _error(request: Request, status: int, code: str, message: str,
           headers: dict[str, str] | None = None, details: list | None = None) -> JSONResponse:
    body: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    if details:
        body["details"] = details
    return JSONResponse(status_code=status, content={"error": body}, headers=headers)


ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 403: {"model": ErrorResponse},
    404: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = DetectionService(settings)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    log = _configure_app_logger()

    app = FastAPI(
        title="AI Prompt Injection Detector (DFA)",
        version=DETECTOR_VERSION,
        description=(
            "Deterministic, local prompt-injection detection with a token-level Aho-Corasick DFA. "
            "Detects a predefined, configurable REGULAR subset of injection phrases; it does not "
            "understand semantics and cannot detect every prompt injection."
        ),
    )
    app.state.service = service
    app.state.settings = settings
    app.state.limiter = limiter

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After"],
        )

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        start = time.perf_counter()
        incoming = request.headers.get("x-request-id", "")
        request.state.request_id = incoming if _REQUEST_ID_RE.match(incoming) else str(uuid.uuid4())

        length = request.headers.get("content-length")
        if length is not None:
            try:
                too_large = int(length) > settings.max_body_bytes
            except ValueError:
                too_large = True
            if too_large:
                response = _error(request, 413, "payload_too_large",
                                  f"Request body exceeds {settings.max_body_bytes} bytes.")
                return _finish(request, response, start)
        try:
            response = await call_next(request)
        except Exception:  # pragma: no cover - defensive; handlers below catch most errors
            log.exception("unhandled error")
            response = _error(request, 500, "internal_error", "Internal server error.")
        return _finish(request, response, start)

    def _finish(request: Request, response, start: float):
        response.headers["X-Request-ID"] = request.state.request_id
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if not request.url.path.startswith(DOCS_PATHS):
            response.headers.setdefault("Content-Security-Policy", API_CSP)
        duration_ms = round((time.perf_counter() - start) * 1000, 3)
        route = request.scope.get("route")
        path_label = getattr(route, "path", request.url.path) if route else "<unmatched>"
        service.metrics.record_request(path_label, response.status_code)
        log.info(json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": "INFO", "event": "http_request", "request_id": request.state.request_id,
            "method": request.method, "path": path_label, "status": response.status_code,
            "duration_ms": duration_ms,
        }))
        return response

    # -------------------------------------------------------- error handlers
    @app.exception_handler(APIError)
    async def _api_error(request: Request, exc: APIError):
        return _error(request, exc.status, exc.code, exc.message, exc.headers, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        # Never echo the submitted values back (they may be sensitive prompts).
        details = [
            {"loc": [str(p) for p in err.get("loc", ())], "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in exc.errors()
        ]
        return _error(request, 422, "validation_error", "Request body failed validation.", details=details)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return _error(request, exc.status_code, code, str(exc.detail))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.error(json.dumps({"event": "unhandled_exception", "request_id": request.state.request_id,
                              "type": type(exc).__name__}))
        return _error(request, 500, "internal_error", "Internal server error.")

    # ---------------------------------------------------------- dependencies
    def require_api_key(request: Request) -> None:
        if not settings.api_key:
            return
        supplied = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(supplied.encode(), settings.api_key.encode()):
            raise APIError(401, "unauthorized", "Missing or invalid X-API-Key header.")

    def rate_limit(request: Request) -> None:
        key = request.headers.get("x-api-key") or (request.client.host if request.client else "unknown")
        allowed, retry_after = limiter.check(key)
        if not allowed:
            raise APIError(429, "rate_limited",
                           f"Rate limit of {limiter.limit} requests/minute exceeded.",
                           headers={"Retry-After": str(retry_after)})

    protected = [Depends(require_api_key), Depends(rate_limit)]

    # ---------------------------------------------------------------- routes
    @app.get("/", tags=["status"])
    def index() -> dict[str, Any]:
        """Landing response so opening the base URL in a browser is not a 404."""
        return {
            "service": "AI Prompt Injection Detector (DFA)",
            "status": "ok",
            "detector_version": DETECTOR_VERSION,
            "docs": "/docs",
            "endpoints": {
                "health": "GET /health",
                "ready": "GET /ready",
                "detect": "POST /v1/detect",
                "patterns": "GET /v1/patterns",
                "metrics": "GET /v1/metrics",
            },
            "dashboard": "Run ./run_local.sh dashboard and open http://127.0.0.1:8501",
        }

    @app.get("/health", tags=["status"])
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "detector_version": DETECTOR_VERSION,
            "uptime_seconds": round(time.time() - service.started_at, 1),
        }

    @app.get("/ready", tags=["status"])
    def ready():
        report = service.readiness()
        return JSONResponse(status_code=200 if report["ready"] else 503, content=report)

    @app.post("/v1/detect", response_model=DetectResponse, dependencies=protected,
              responses=ERROR_RESPONSES, tags=["detection"])
    def detect(body: DetectRequest, request: Request) -> dict[str, Any]:
        try:
            return service.analyze(
                body.text,
                policy=body.policy,
                include_trace=body.include_trace,
                request_id=request.state.request_id,
                client_ip=request.client.host if request.client else None,
            )
        except InputValidationError as exc:
            status = 413 if exc.code == "input_too_long" else 422
            raise APIError(status, exc.code, exc.message) from None
        except UnknownPolicyError as exc:
            raise APIError(400, "unknown_policy",
                           f"Unknown policy {exc.args[0]!r}. Available: {sorted(service.scoring.policies)}") from None

    @app.get("/v1/patterns", response_model=RulesResponse, dependencies=protected, tags=["rules"])
    def patterns() -> dict[str, Any]:
        return service.rules_report()

    @app.patch("/v1/patterns/{rule_id}", response_model=RulesResponse, dependencies=protected,
               responses=ERROR_RESPONSES, tags=["rules"])
    def toggle_rule(rule_id: str, body: RuleToggleRequest) -> dict[str, Any]:
        try:
            return service.set_rule_enabled(rule_id, body.enabled)
        except RuleEditingDisabledError as exc:
            raise APIError(403, "rule_editing_disabled", str(exc)) from None
        except KeyError:
            raise APIError(404, "rule_not_found", f"No rule with id {rule_id!r}.") from None
        except (RuleConfigError, AutomatonBuildError) as exc:
            raise APIError(422, "invalid_rule_configuration", str(exc)) from None

    @app.post("/v1/patterns", response_model=RulesResponse, status_code=201, dependencies=protected,
              responses=ERROR_RESPONSES, tags=["rules"])
    def create_rule(body: RuleCreateRequest) -> dict[str, Any]:
        try:
            return service.add_rule(body.model_dump(mode="json"))
        except RuleEditingDisabledError as exc:
            raise APIError(403, "rule_editing_disabled", str(exc)) from None
        except RuleConfigError as exc:
            raise APIError(422, "invalid_rule_configuration", "Rule rejected.", details=exc.problems) from None
        except AutomatonBuildError as exc:
            raise APIError(422, "invalid_rule_configuration", str(exc)) from None

    @app.get("/v1/policies", dependencies=protected, tags=["rules"])
    def policies() -> dict[str, Any]:
        return service.scoring.model_dump(mode="json")

    @app.get("/v1/automaton", dependencies=protected, tags=["automaton"])
    def automaton(include_states: bool = False) -> dict[str, Any]:
        return service.automaton_report(include_states=include_states)

    @app.get("/v1/automaton/states/{state}", dependencies=protected, responses=ERROR_RESPONSES,
             tags=["automaton"])
    def automaton_state(state: int) -> dict[str, Any]:
        try:
            return service.state_report(state)
        except IndexError:
            raise APIError(404, "state_not_found",
                           f"State q{state} does not exist (|Q| = {service.detector.automaton.num_states}).") from None

    @app.get("/v1/metrics", dependencies=protected, tags=["status"])
    def metrics() -> dict[str, Any]:
        snap = service.metrics.snapshot()
        snap["detector_version"] = DETECTOR_VERSION
        snap["ruleset_fingerprint"] = service.detector.ruleset.fingerprint
        snap["config"] = {
            "auth_enabled": settings.auth_enabled,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "max_input_chars": settings.max_input_chars,
            "max_body_bytes": settings.max_body_bytes,
            "rule_editing_enabled": settings.rule_editing_enabled,
            "audit_raw_input": settings.audit_log_raw_input,
            "audit_input_hash": ("hmac-sha256" if settings.audit_hash_key else "sha256")
            if settings.audit_hash_input else "off",
            "default_policy": service.default_policy,
        }
        return snap

    @app.get("/v1/evaluation", dependencies=protected, responses=ERROR_RESPONSES, tags=["evaluation"])
    def evaluation(
        split: str = Query("all", description=f"One of {SPLITS}"),
        policy: str | None = Query(None),
        positive_on: str = Query("flag", description=f"One of {POSITIVE_MODES}"),
    ) -> dict[str, Any]:
        if split not in SPLITS or positive_on not in POSITIVE_MODES:
            raise APIError(400, "invalid_parameter", f"split must be in {SPLITS}, positive_on in {POSITIVE_MODES}.")
        try:
            corpus = load_corpus(settings.corpus_path)
            return evaluate(service, corpus, split=split, policy=policy, positive_on=positive_on)
        except UnknownPolicyError as exc:
            raise APIError(400, "unknown_policy", f"Unknown policy {exc.args[0]!r}.") from None
        except CorpusError as exc:
            raise APIError(500, "corpus_error", str(exc)) from None

    return app


_default_app: FastAPI | None = None


def __getattr__(name: str) -> FastAPI:
    """Build the module-level ``app`` lazily (PEP 562).

    ``uvicorn src.api:app`` triggers this on first access, while tests can
    ``from src.api import create_app`` without touching the real config or logs.
    """
    global _default_app
    if name == "app":
        if _default_app is None:
            _default_app = create_app()
        return _default_app
    raise AttributeError(name)
