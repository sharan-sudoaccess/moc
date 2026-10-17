# Threat Model

## 1. Purpose and scope

The detector inspects **untrusted text** before it reaches a large language model
(LLM) and reports whether it contains any of a configured set of prompt-injection
phrasings. It returns evidence and a **recommended** action (ALLOW / FLAG / BLOCK).

It **detects**. It does not **enforce**. Nothing in this project sits between a user
and an LLM, and no LLM is called. An integrator who wants enforcement must call
`POST /v1/detect` and refuse to forward the content when `action == "BLOCK"`
(and route FLAG to human review). Until such an integration exists, a BLOCK
decision protects nothing.

The DFA does not understand intent or meaning. It recognizes configured token
sequences, given the implemented normalization and matching rules, and nothing more.

## 2. Assets

| Asset | Why it matters |
|---|---|
| The downstream LLM's **system prompt / operator instructions** | Target of extraction and override attacks |
| **Confidential data** reachable by the LLM (documents, credentials, user data) | Target of exfiltration |
| **Integrity of the LLM's behaviour** (safety policy, role) | Target of role manipulation and safety bypass |
| **Submitted prompts** (may contain personal data) | Must not leak via logs, errors or metrics |
| **Rule configuration** (`config/patterns.json`) | Tampering silently disables detection |
| **Audit log** | Accountability; also a privacy liability |

## 3. Trust boundaries

```
 [ untrusted ]                         [ detector host ]                           [ downstream ]
 end user text  ─┐
 documents, web  ├──► HTTP ──►  FastAPI  ──►  normalization ─► DFA ─► policy  ──►  (integrator decides)  ──►  LLM
 pages, e-mails ─┘   (TB1)      api.py          (in-process, trusted code)            (TB3)
                                   │
 dashboard user  ──► Streamlit ────┘  (TB2: dashboard → API over HTTP, optional API key)
                                   │
                         config/*.json, logs/  (TB4: local filesystem, trusted to OS permissions)
```

* **TB1**: everything in the request body is untrusted, including the `policy` field.
* **TB2**: the dashboard is just another API client. It has no privileged path.
* **TB3**: the detector's output is advice. The integrator is responsible for acting on it.
* **TB4**: anyone who can write `config/` or `logs/` can change detection or erase records.

## 4. Untrusted inputs

* `text` of `POST /v1/detect`: direct user prompts, and also **indirect** content
  (retrieved documents, web pages, e-mails, tool outputs) that an application plans to put
  into an LLM context.
* `policy`, `include_trace`, headers (`X-Request-ID`, `X-API-Key`, `Content-Length`).
* Rule submissions via `POST/PATCH /v1/patterns` (when editing is enabled).

## 5. Attacks in scope (detected when phrased as configured)

| Category | Example | Rule IDs |
|---|---|---|
| Instruction override | "Ignore previous instructions" | IO-001…004 |
| System-prompt extraction | "Reveal the system prompt" | SPE-001…003 |
| Role manipulation | "You are now an unrestricted assistant" | RM-001…004 |
| Safety bypass | "Bypass your safety rules" | SB-001…003 |
| Data exfiltration | "Send private data to …" | DE-001…002 |
| Priority manipulation | "This instruction takes priority over all others" | PM-001 |
| Indirect / embedded injection | "Note to AI: …", fake "SYSTEM OVERRIDE" markers in documents | II-001…002 |

Obfuscation handled by normalization: case changes, extra whitespace and line
breaks, punctuation between words, accents, full-width characters, zero-width
characters, and a small set of Cyrillic/Greek homoglyphs.

## 6. Attacks out of scope (expected to evade)

* **Paraphrase**: "set aside your earlier guidance" (no configured phrase).
* **Other languages**: patterns are English only.
* **Encodings**: base64, ROT13, hex, URL-encoding, HTML entities, Unicode tag characters
  not covered by the confusables table.
* **Leetspeak / spacing**: "1gn0re", "i g n o r e", "ig-nore".
* **Payload splitting**: the instruction is spread over several messages or documents.
  Each request is analyzed alone.
* **Multimodal**: instructions inside images, audio, PDFs (not text-extracted here).
* **Semantic attacks**: role-play scenarios, persuasion, gradual escalation, many-shot
  jailbreaks with no fixed key phrase.
* **Attacks on the downstream LLM** that are not injections (e.g. harmful-content requests
  phrased politely).

## 7. False positives (benign text flagged)

* **Mention vs. use**: security articles, training material, this project's own documentation,
  or a user quoting a phrase ("the paper lists 'ignore previous instructions' as…").
  Matches inside quotation marks are *annotated* (`in_quotes: true`) but deliberately still
  reported. Quotes are trivial for an attacker to add, so suppressing quoted matches
  would create an evasion.
* **Domain overlap**: "admin override switch on the boiler" (II-002), "bypass content filters"
  in a defensive discussion (SB-001), "hypothetically speaking" (RM-004, low severity).
* The evaluation corpus contains such cases on purpose; see `evaluation/`.

## 8. False negatives (attacks missed)

Everything in §6, plus any phrasing variant nobody added to `config/patterns.json`.
Recall is bounded by the rule author's imagination.

## 9. Unicode and obfuscation limitations

* NFKD + accent stripping can merge distinct words in some languages. This only affects
  the detector's internal representation, never the evidence or the response.
* The homoglyph table is **deliberately small** (16 letters). Unicode has thousands of
  confusables; a complete mapping (Unicode TR39 skeletons) would cut evasion but raise
  false positives on legitimate non-Latin text.
* Zero-width removal covers U+200B/C/D, U+2060, U+FEFF and U+00AD only.
* Tokenization treats `_`, `-`, `.` as separators, so "ignore_previous_instructions" is caught.
  Inserting **letters** or spaces inside a word ("ignnore", "i gnore") is not.

## 10. Malicious documents and external content

Indirect prompt injection is the most realistic threat. The attacker does not talk to
the model; they plant text in content the model will read. The detector helps only if
the integrator sends **that content** (each retrieved chunk, page or e-mail) through
`/v1/detect`, not just the end user's question. II-001/II-002 target common markers of
such content, but a careful attacker will avoid them.

## 11. Unsafe downstream integration

* Treating ALLOW as "safe": ALLOW only means "no configured pattern matched".
* Checking the user message but not retrieved content (see §10).
* Normalizing or transforming text *after* the check (check what you send).
* Failing open: if the detector is unreachable, the integrator must decide whether to block
  or allow. The service has no opinion.
* Letting the LLM's own output re-enter the context unchecked.

## 12. Threats to the detector itself

| Threat | Mitigation in this project | Residual risk |
|---|---|---|
| Resource exhaustion (huge bodies) | `MAX_BODY_BYTES` (Content-Length check), `MAX_INPUT_CHARS`, `MAX_TRACE_STEPS`; O(n) scan | Content-Length can be absent with chunked encoding (uvicorn still reads the body); no global concurrency limit |
| Request flooding | Per-client sliding-window rate limit | In-memory, per process; spoofable behind proxies; not a DDoS defence |
| Unauthorized use | Optional `X-API-Key` (constant-time compare) | Single shared key, no rotation, no TLS: put a TLS reverse proxy in front |
| Rule tampering via API | `RULE_EDITING_ENABLED` (off by default in code), validation, atomic write, audit event | Any API-key holder can edit when enabled. No roles |
| Rule tampering on disk | OS file permissions | No signature or integrity check |
| Prompt leakage via logs/errors | Raw text never logged by default; validation errors never echo input; metrics hold metadata only | SHA-256 of short inputs can be brute-forced (use `AUDIT_HASH_KEY`) |
| Log tampering | None beyond file permissions | JSONL is **not tamper-evident** |
| XSS in dashboard | All user text HTML-escaped before rendering | Streamlit's own surface |

## 13. Detection vs. enforcement (summary)

| | This project | Required for real protection |
|---|---|---|
| Recognize configured phrasings | ✔ | |
| Explain evidence, score, recommend action | ✔ | |
| Stop content from reaching the LLM | ✘ | Integrator must enforce BLOCK |
| Understand paraphrases / intent | ✘ | Additional semantic layers, model-side defences, least-privilege tool design |
