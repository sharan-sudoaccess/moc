"""AI Prompt Injection Detector using a Deterministic Finite Automaton (DFA).

Package layout (pipeline order):

    normalization.py  -> input validation, Unicode normalization, tokenization
    rules.py          -> load and validate the JSON rule configuration
    automaton.py      -> the token-level Aho-Corasick DFA (the core recognizer)
    detector.py       -> compiles rules into the DFA and turns raw matches into evidence
    scoring.py        -> risk score, risk level and ALLOW / FLAG / BLOCK policy
    audit.py          -> privacy-preserving structured audit log (JSON Lines)
    metrics.py        -> in-memory request / detection metrics and rate limiting
    service.py        -> orchestrates the whole pipeline (used by API and evaluation)
    evaluation.py     -> precision / recall / F1 over a labeled corpus
    api.py            -> FastAPI application
"""

from src.config import DETECTOR_VERSION

__all__ = ["DETECTOR_VERSION"]
