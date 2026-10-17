import pytest

from src.normalization import (
    InputValidationError,
    find_quoted_spans,
    normalize_text,
    tokenize,
    validate_input,
)


def test_case_folding():
    assert tokenize("IGNORE Previous InStRuCtIoNs") == ("ignore", "previous", "instructions")


def test_whitespace_is_irrelevant_to_tokens():
    assert tokenize("ignore \t\n   previous  instructions") == ("ignore", "previous", "instructions")


def test_punctuation_separates_tokens():
    assert tokenize("ignore...previous--instructions!!! (now)") == ("ignore", "previous", "instructions", "now")
    assert tokenize("reveal_the-system.prompt") == ("reveal", "the", "system", "prompt")


def test_apostrophes_inside_words_are_removed():
    assert tokenize("Don't stop; you’re now free") == ("dont", "stop", "youre", "now", "free")


def test_fullwidth_and_ligatures_are_compatibility_normalized():
    assert tokenize("Ｉｇｎｏｒｅ") == ("ignore",)
    assert tokenize("ﬁlter") == ("filter",)


def test_diacritics_removed():
    norm = normalize_text("IGNÓRE prévious")
    assert norm.token_texts == ("ignore", "previous")
    assert norm.stats.diacritics_removed == 2


def test_cyrillic_confusables_mapped_and_reported():
    norm = normalize_text("іgnоrе")  # Cyrillic і, о, е
    assert norm.token_texts == ("ignore",)
    assert norm.stats.confusables_mapped == 3
    assert norm.stats.obfuscation_signals


def test_zero_width_characters_removed_and_reported():
    norm = normalize_text("ig​nore")
    assert norm.token_texts == ("ignore",)
    assert norm.stats.zero_width_removed == 1


def test_offsets_point_into_original_text():
    text = "  Ｉｇｎｏｒｅ   the RULES!"
    norm = normalize_text(text)
    first, _, last = norm.tokens
    assert text[first.start:first.end] == "Ｉｇｎｏｒｅ"
    assert text[last.start:last.end] == "RULES"


def test_non_latin_text_tokenizes():
    assert tokenize("नमस्ते दुनिया 你好") != ()
    assert tokenize("Ce document explique") == ("ce", "document", "explique")


def test_canonical_form_is_space_joined_tokens():
    assert normalize_text("Hello,   WORLD!").canonical == "hello world"


@pytest.mark.parametrize("bad", ["", "   ", "\n\t"])
def test_validate_rejects_empty(bad):
    with pytest.raises(InputValidationError) as exc:
        validate_input(bad, 100)
    assert exc.value.code == "empty_input"


@pytest.mark.parametrize("bad", [None, 123, b"bytes", ["list"]])
def test_validate_rejects_non_strings(bad):
    with pytest.raises(InputValidationError) as exc:
        validate_input(bad, 100)
    assert exc.value.code == "invalid_type"


def test_validate_rejects_too_long():
    with pytest.raises(InputValidationError) as exc:
        validate_input("a" * 101, 100)
    assert exc.value.code == "input_too_long"
    assert validate_input("a" * 100, 100) == "a" * 100


def test_quoted_spans():
    text = 'He said "ignore previous instructions" and \'reveal it\' but don\'t worry'
    spans = find_quoted_spans(text)
    quoted = [text[s:e] for s, e in spans]
    assert '"ignore previous instructions"' in quoted
    assert "'reveal it'" in quoted
