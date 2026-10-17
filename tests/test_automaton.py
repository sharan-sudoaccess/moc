"""Formal properties of the DFA (independent of the security rule set)."""

import random

import pytest

from src.automaton import OTHER_SYMBOL, SKIP_SYMBOL, AutomatonBuildError, TokenAutomaton

PATTERNS = [("a", "b"), ("b",), ("b", "c", "a"), ("a", "b", "c", "a", "b"), ("c",)]


def brute_force(patterns, tokens, skip=frozenset()):
    """Reference matcher: delete skip tokens, then compare every window."""
    kept = [(i, t) for i, t in enumerate(tokens) if t not in skip]
    found = []
    for pid, p in enumerate(patterns):
        for s in range(len(kept) - len(p) + 1):
            if tuple(t for _, t in kept[s:s + len(p)]) == p:
                found.append((pid, kept[s][0], kept[s + len(p) - 1][0]))
    return sorted(found)


def test_transition_function_is_total_and_deterministic():
    a = TokenAutomaton(PATTERNS, skip_tokens=["the"])
    assert len(a.delta) == a.num_states
    for row in a.delta:
        assert len(row) == len(a.alphabet)  # exactly one target per (state, symbol)
        assert all(0 <= q < a.num_states for q in row)


def test_alphabet_is_vocabulary_plus_two_classes():
    a = TokenAutomaton(PATTERNS, skip_tokens=["the"])
    assert a.alphabet == ("a", "b", "c", SKIP_SYMBOL, OTHER_SYMBOL)
    assert a.symbol_of("zebra") == a.other_symbol
    assert a.symbol_of("the") == a.skip_symbol


def test_states_are_trie_nodes_numbered_breadth_first():
    a = TokenAutomaton(PATTERNS)
    depths = [len(lbl) for lbl in a.labels]
    assert depths == sorted(depths)
    assert a.state_label(0) == "ε"
    # trie of the 5 patterns has 10 nodes
    assert a.num_states == 10


def test_failure_links_point_to_longest_proper_suffix_state():
    a = TokenAutomaton(PATTERNS)
    labels = {a.labels[q]: q for q in range(a.num_states)}
    for q in range(1, a.num_states):
        label = a.labels[q]
        expected = 0
        for k in range(1, len(label)):
            if label[k:] in labels:
                expected = labels[label[k:]]
                break
        assert a.fail[q] == expected, (label, a.fail[q], expected)


def test_skip_is_self_loop_and_other_resets():
    a = TokenAutomaton(PATTERNS, skip_tokens=["the"])
    for q in range(a.num_states):
        assert a.delta[q][a.skip_symbol] == q
        assert a.delta[q][a.other_symbol] == 0


def test_accepting_states_are_exactly_states_with_output():
    a = TokenAutomaton(PATTERNS)
    for q in range(a.num_states):
        assert (q in a.accepting) == bool(a.output[q])


def test_overlapping_and_nested_matches_all_reported():
    a = TokenAutomaton(PATTERNS)
    result = a.run(["a", "b", "c", "a", "b"])
    got = sorted((m.pattern_id, m.start_pos, m.end_pos) for m in result.matches)
    assert got == brute_force(PATTERNS, ["a", "b", "c", "a", "b"])
    assert (3, 0, 4) in got and (0, 3, 4) in got and (2, 1, 3) in got


@pytest.mark.parametrize("seed", range(5))
def test_equivalent_to_brute_force_on_random_inputs(seed):
    rng = random.Random(seed)
    skip = frozenset({"s"})
    a = TokenAutomaton(PATTERNS, skip_tokens=skip)
    for _ in range(400):
        tokens = [rng.choice("abcxs") for _ in range(rng.randint(0, 20))]
        got = sorted((m.pattern_id, m.start_pos, m.end_pos) for m in a.run(tokens).matches)
        assert got == brute_force(PATTERNS, tokens, skip)


def test_same_input_same_transitions():
    a = TokenAutomaton(PATTERNS)
    tokens = list("abcabxcab")
    r1, r2 = a.run(tokens, trace=True), a.run(tokens, trace=True)
    assert r1 == r2


def test_trace_records_actual_delta_applications():
    a = TokenAutomaton(PATTERNS, skip_tokens=["the"])
    tokens = ["a", "the", "b", "zzz"]
    result = a.run(tokens, trace=True)
    assert len(result.trace) == len(tokens)
    state = 0
    for step, tok in zip(result.trace, tokens):
        assert step.from_state == state
        assert step.to_state == a.step(state, tok)
        state = step.to_state
    kinds = [s.transition for s in result.trace]
    assert kinds == ["trie", "skip", "trie", "reset"]
    assert result.trace[2].outputs == (0, 1)  # "a b" and "b" recognized together


def test_failure_transition_kind_reported():
    a = TokenAutomaton([("a", "b", "c"), ("b", "d")])
    result = a.run(["a", "b", "d"], trace=True)
    assert result.trace[2].transition == "failure"  # from "a b", d continues "b d"
    assert [m.pattern_id for m in result.matches] == [1]


def test_skip_tokens_do_not_reemit_matches():
    a = TokenAutomaton([("b",)], skip_tokens=["s"])
    assert len(a.run(["b", "s", "s", "s"]).matches) == 1


def test_trace_truncation():
    a = TokenAutomaton([("a",)])
    result = a.run(["a"] * 10, trace=True, max_trace_steps=3)
    assert len(result.trace) == 3 and result.trace_truncated
    assert len(result.matches) == 10  # detection itself is never truncated


def test_empty_pattern_set_is_single_state_machine():
    a = TokenAutomaton([])
    assert a.num_states == 1
    assert a.run(["anything"]).matches == ()


@pytest.mark.parametrize(
    "patterns, skip",
    [([()], []), ([("a",), ("a",)], []), ([("the", "x")], ["the"]), ([("a", "")], [])],
)
def test_invalid_patterns_rejected(patterns, skip):
    with pytest.raises(AutomatonBuildError):
        TokenAutomaton(patterns, skip_tokens=skip)
