"""Stage 1-3 of the pipeline: input validation, text normalization, tokenization.

The DFA never sees raw text. It sees a sequence of *tokens* produced here.

Normalization is applied character by character so that every normalized
character remembers which character of the ORIGINAL input it came from.
That offset map lets the detector report evidence (matched phrase and
character span) in terms of the text the user actually submitted, even
though matching happens on the normalized representation.

Normalization steps (per original character):

1. Zero-width / invisible formatting characters are dropped
   (U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD).
2. Unicode compatibility decomposition (NFKD): full-width letters,
   ligatures and similar compatibility forms become plain letters.
3. Combining marks (accents) are dropped: "ignóre" -> "ignore".
4. Case folding (``str.casefold``), stronger than ``lower()``.
5. A *small, conservative* confusables table maps Cyrillic/Greek letters
   that are visually identical to Latin letters ("іgnоrе" written with
   Cyrillic і/о/е -> "ignore"). It is deliberately incomplete; see
   docs/limitations.md.
6. Typographic apostrophes are unified to "'" and all whitespace becomes " ".

Tokenization then extracts maximal runs of Unicode letters/digits; an
apostrophe inside a word is removed ("don't" -> "dont"). Every other
character (punctuation, underscores, hyphens, quotes, emoji) is a separator,
so "ignore-previous_instructions!!!" yields three tokens.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH_CHARS = frozenset({"​", "‌", "‍", "⁠", "﻿", "­"})

# Conservative confusables map: only lowercase letters that are rendered
# (near-)identically to a Latin letter in common fonts. Applied after casefold.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a",  # а
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "с": "c",  # с
    "х": "x",  # х
    "у": "y",  # у
    "і": "i",  # і
    "ј": "j",  # ј
    "ѕ": "s",  # ѕ
    "һ": "h",  # һ
    "ԁ": "d",  # ԁ
    # Greek
    "ο": "o",  # ο omicron
    "ι": "i",  # ι iota
    "κ": "k",  # κ kappa
    "ν": "v",  # ν nu
}

APOSTROPHES = frozenset({"'", "’", "‘", "ʼ", "＇"})

# A token is a run of Unicode letters/digits, optionally joined by apostrophes.
_TOKEN_RE = re.compile(r"[^\W_]+(?:'[^\W_]+)*")

# Quoted regions in the ORIGINAL text. Used only to annotate matches
# ("mention vs. use"), never to suppress them.
_QUOTE_RE = re.compile(
    r'"[^"\n]{1,2000}"'
    r"|“[^”\n]{1,2000}”"
    r"|‘[^’\n]{1,2000}’"
    r"|«[^»\n]{1,2000}»"
    r"|`[^`\n]{1,2000}`"
    r"|(?<![\w'])'[^'\n]{1,2000}'(?![\w'])"
)


class InputValidationError(ValueError):
    """Raised when submitted text is not acceptable for analysis."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Token:
    """One token of the normalized input.

    ``text`` is the normalized token (what the DFA consumes).
    ``start``/``end`` are character offsets into the ORIGINAL input.
    """

    index: int
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class NormalizationStats:
    zero_width_removed: int = 0
    diacritics_removed: int = 0
    confusables_mapped: int = 0
    compatibility_changes: int = 0

    @property
    def obfuscation_signals(self) -> bool:
        return bool(self.zero_width_removed or self.confusables_mapped)


@dataclass(frozen=True)
class NormalizedText:
    original_length: int
    tokens: tuple[Token, ...]
    stats: NormalizationStats = field(default_factory=NormalizationStats)

    @property
    def canonical(self) -> str:
        """The representation the detector works on: tokens joined by one space."""
        return " ".join(t.text for t in self.tokens)

    @property
    def token_texts(self) -> tuple[str, ...]:
        return tuple(t.text for t in self.tokens)


def validate_input(text: object, max_chars: int) -> str:
    """Pipeline stage 1. Returns the text unchanged if it is acceptable."""
    if not isinstance(text, str):
        raise InputValidationError("invalid_type", "Input text must be a string.")
    if len(text) > max_chars:
        raise InputValidationError(
            "input_too_long",
            f"Input text has {len(text)} characters; the configured maximum is {max_chars}.",
        )
    if text.strip() == "":
        raise InputValidationError("empty_input", "Input text is empty or contains only whitespace.")
    return text


def _normalize_char(ch: str, counters: dict[str, int]) -> str:
    if ch in ZERO_WIDTH_CHARS:
        counters["zero_width_removed"] += 1
        return ""
    decomposed = unicodedata.normalize("NFKD", ch)
    if decomposed != ch and not any(unicodedata.combining(c) for c in decomposed):
        counters["compatibility_changes"] += 1
    pieces: list[str] = []
    for part in decomposed:
        if unicodedata.combining(part):
            counters["diacritics_removed"] += 1
            continue
        for folded in part.casefold():
            if folded in CONFUSABLES:
                counters["confusables_mapped"] += 1
                folded = CONFUSABLES[folded]
            elif folded in APOSTROPHES:
                folded = "'"
            elif folded.isspace():
                folded = " "
            pieces.append(folded)
    return "".join(pieces)


def normalize_text(text: str) -> NormalizedText:
    """Pipeline stages 2-3: normalize ``text`` and split it into tokens."""
    counters = {
        "zero_width_removed": 0,
        "diacritics_removed": 0,
        "confusables_mapped": 0,
        "compatibility_changes": 0,
    }
    chars: list[str] = []
    origin: list[int] = []  # origin[k] = index in `text` of normalized char k
    for i, ch in enumerate(text):
        for out in _normalize_char(ch, counters):
            chars.append(out)
            origin.append(i)
    normalized = "".join(chars)

    tokens: list[Token] = []
    for m in _TOKEN_RE.finditer(normalized):
        token_text = m.group().replace("'", "")
        tokens.append(
            Token(
                index=len(tokens),
                text=token_text,
                start=origin[m.start()],
                end=origin[m.end() - 1] + 1,
            )
        )
    return NormalizedText(
        original_length=len(text),
        tokens=tuple(tokens),
        stats=NormalizationStats(**counters),
    )


def tokenize(text: str) -> tuple[str, ...]:
    """Convenience: normalized token strings only."""
    return normalize_text(text).token_texts


def find_quoted_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of quoted regions in the original text (heuristic)."""
    return [(m.start(), m.end()) for m in _QUOTE_RE.finditer(text)]
