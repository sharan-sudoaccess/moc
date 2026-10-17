# Limitations

This project is an educational detector, not a product. It has been tested
locally (see `docs/verification.md`). It has **not** had a security review, a load
test, or production deployment validation, and it is **not production-ready**.

## Detection

* Detects a **predefined, regular subset** of prompt-injection phrasings (219 phrase
  variants in 19 rules). It does not understand meaning, intent or context.
* **Paraphrases evade it**: "Set aside your earlier guidance…" scores 0.
* **Quoted or discussed attacks trigger it**: "The article contains the phrase
  'ignore previous instructions'" is flagged. Matches are annotated `in_quotes`, not suppressed.
* English only. Leetspeak, letter spacing, encodings (base64 etc.) and most Unicode
  confusables are not normalized.
* Filler words (⟨skip⟩) are ignored anywhere between pattern words, and sentence
  boundaries are not modelled. "Ignore. The previous instructions were wrong." still
  contains the token sequence `ignore previous instructions` and is flagged.
* Each request is analyzed independently: no conversation history, no payload splitting.

## Scoring and policy

* Severity weights (0.15 / 0.35 / 0.60 / 0.85), risk bands (30 / 60 / 85) and policy
  thresholds are **illustrative, hand-chosen values**. They are not calibrated on data
  or scientifically validated. They are configurable in `config/policies.json`.
* Noisy-OR treats categories as independent evidence, which they are not.

## Evaluation

* The corpus (90 examples) is small and was **written by the same author as the rules**.
  The `heldout` split was written before the first evaluation run and was never used for
  tuning, but it is not an independent benchmark. The numbers are illustrative only.
* The dev split scores better than the held-out split (F1 0.914 vs 0.792), which is
  the expected sign of rules fitted to the examples their author could see.

## Service

* **Metrics and rate limiting are in memory**: they reset on restart and are per process.
  With `uvicorn --workers N`, each worker counts separately, so the effective limit is N×.
* The rate-limit key is the API key or the client IP. Behind a reverse proxy all clients
  share the proxy's IP unless uvicorn's `--proxy-headers` and `--forwarded-allow-ips` are set.
* The `Content-Length` check does not cover chunked requests; the per-field
  `MAX_INPUT_CHARS` check still applies after parsing.
* No TLS: run behind a TLS-terminating reverse proxy for anything beyond localhost.
* One shared API key; no users, roles, key rotation or expiry.
* Swagger UI (`/docs`) loads its JavaScript/CSS from a CDN. Offline, `/docs` shows a blank
  page, but `/openapi.json` and the API itself work.
* Rule edits from the dashboard are persisted to `config/patterns.json`. In Docker, the
  file lives inside the container and is lost when the container is recreated.

## Audit log

* JSON Lines file with size-based rotation (`AUDIT_MAX_BYTES` × (`AUDIT_BACKUP_COUNT`+1)
  bounds disk use). Older files are deleted by rotation; there is no retention policy beyond that.
* **Not tamper-evident**: anyone with write access to `logs/` can edit or delete records.
* Local file permissions (0640 attempted) are the only access control.
* Records written just before a crash may be lost (no fsync per record).
* No centralized collection, alerting or monitoring.
* **Hashes are not anonymization.** A plain SHA-256 of a short or predictable prompt can be
  recovered by hashing guesses. Set `AUDIT_HASH_KEY` to use HMAC-SHA256, or disable
  hashing with `AUDIT_HASH_INPUT=false`. Even keyed hashes let anyone holding the key
  test guesses, and they link repeated submissions of the same text.
