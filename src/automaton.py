"""The core recognizer: a token-level Aho-Corasick automaton compiled to a DFA.

Formal model (see docs/mathematical_model.md for the full write-up)
-------------------------------------------------------------------
    M = (Q, Σ, δ, q0, F)  plus an output function  λ : F -> P(patterns)

    Σ  = V ∪ {⟨skip⟩, ⟨other⟩}
         V        = every distinct token that occurs in some configured pattern
         ⟨skip⟩   = the class of configured "ignorable" filler tokens (the, your, ...)
         ⟨other⟩  = the class of every other token (any word not in V)
       Mapping an arbitrary input token to one of these |V|+2 symbols is
       itself a total function, so the alphabet is finite even though the
       set of possible English words is not.

    Q  = the nodes of the pattern trie. State q is identified with the token
         sequence on the path from the root to q ("the longest pattern
         prefix that is a suffix of what has been read so far").
         States are numbered in breadth-first order with children sorted by
         symbol, so numbering is deterministic for a given rule set.

    q0 = the trie root (empty prefix).

    δ  = a TOTAL function Q x Σ -> Q stored as a dense table:
           δ(q, a) = goto(q, a)              if the trie has an edge q -a-> q'
           δ(q, a) = δ(fail(q), a)           otherwise, for q != q0
           δ(q0, a) = q0                     if the root has no a-edge
           δ(q, ⟨skip⟩)  = q                 (self-loop: filler words are ignored)
           δ(q, ⟨other⟩) = q0                (no pattern contains an unknown word)
         The failure function is used ONLY at construction time to fill the
         table. At run time every step is one table lookup, i.e. the machine
         is a genuine DFA; there is no backtracking and no failure-chain walk.

    F  = { q in Q : λ(q) != ∅ }, where λ(q) is the set of patterns that are
         a suffix of the label of q (the pattern ending at q itself plus all
         patterns reachable through failure/"dictionary suffix" links).

Outputs are emitted when the machine ENTERS a state of F on a non-skip
symbol (Mealy-style output on transitions), so a run of filler words after
a match does not re-report the same match.

Complexity: construction O(|Q| * |Σ|) time and space for the dense table;
scanning n tokens is O(n + z) where z is the number of reported matches.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, Sequence

SKIP_SYMBOL = "⟨skip⟩"
OTHER_SYMBOL = "⟨other⟩"


class AutomatonBuildError(ValueError):
    """Raised when the pattern set cannot be compiled into an automaton."""


@dataclass(frozen=True)
class AutomatonMatch:
    """A pattern recognized during a run.

    ``start_pos``/``end_pos`` are indices into the token sequence passed to
    :meth:`TokenAutomaton.run` (inclusive). ``state`` is the accepting state
    the machine was in when the match was emitted.
    """

    pattern_id: int
    start_pos: int
    end_pos: int
    state: int


@dataclass(frozen=True)
class TraceStep:
    """One application of δ. ``transition`` explains how δ(from, symbol) arose:

    * ``trie``    – a forward edge of the pattern trie (extends a prefix)
    * ``failure`` – a table entry derived through failure links (the read
                    so far ended one prefix, but a shorter suffix continues another)
    * ``reset``   – δ(q, a) = q0 (no pattern prefix survives)
    * ``skip``    – an ignorable filler token: δ(q, ⟨skip⟩) = q
    """

    step: int
    position: int
    token: str
    symbol: str
    from_state: int
    to_state: int
    transition: str
    outputs: tuple[int, ...]


@dataclass(frozen=True)
class RunResult:
    final_state: int
    matches: tuple[AutomatonMatch, ...]
    trace: tuple[TraceStep, ...]
    trace_truncated: bool
    states_visited: int


class TokenAutomaton:
    """Deterministic multi-pattern matcher over token sequences."""

    def __init__(self, patterns: Sequence[Sequence[str]], skip_tokens: Iterable[str] = ()) -> None:
        self.patterns: tuple[tuple[str, ...], ...] = tuple(tuple(p) for p in patterns)
        self.skip_tokens: frozenset[str] = frozenset(skip_tokens)
        self._validate()

        vocabulary = sorted({tok for pattern in self.patterns for tok in pattern})
        self.vocabulary: tuple[str, ...] = tuple(vocabulary)
        self.alphabet: tuple[str, ...] = self.vocabulary + (SKIP_SYMBOL, OTHER_SYMBOL)
        self._symbol_index = {tok: i for i, tok in enumerate(self.vocabulary)}
        self.skip_symbol = len(self.vocabulary)
        self.other_symbol = len(self.vocabulary) + 1

        self._build()

    # ------------------------------------------------------------------ build
    def _validate(self) -> None:
        seen: dict[tuple[str, ...], int] = {}
        for pid, pattern in enumerate(self.patterns):
            if not pattern:
                raise AutomatonBuildError(f"pattern #{pid} is empty")
            for tok in pattern:
                if not tok or not isinstance(tok, str):
                    raise AutomatonBuildError(f"pattern #{pid} contains an empty token")
                if tok in self.skip_tokens:
                    raise AutomatonBuildError(
                        f"pattern #{pid} contains the ignorable token {tok!r}; it could never match"
                    )
            if pattern in seen:
                raise AutomatonBuildError(f"pattern #{pid} duplicates pattern #{seen[pattern]}")
            seen[pattern] = pid

    def _build(self) -> None:
        # 1. Build the trie with temporary node numbers.
        children: list[dict[int, int]] = [{}]
        terminal: list[list[int]] = [[]]
        for pid, pattern in enumerate(self.patterns):
            node = 0
            for tok in pattern:
                sym = self._symbol_index[tok]
                nxt = children[node].get(sym)
                if nxt is None:
                    children.append({})
                    terminal.append([])
                    nxt = len(children) - 1
                    children[node][sym] = nxt
                node = nxt
            terminal[node].append(pid)

        # 2. Renumber states breadth-first, children in symbol order.
        order = [0]
        new_id = {0: 0}
        queue: deque[int] = deque([0])
        while queue:
            old = queue.popleft()
            for sym in sorted(children[old]):
                child = children[old][sym]
                new_id[child] = len(order)
                order.append(child)
                queue.append(child)
        n_states = len(order)

        goto: list[dict[int, int]] = [
            {sym: new_id[c] for sym, c in sorted(children[old].items())} for old in order
        ]
        self._terminal: tuple[tuple[int, ...], ...] = tuple(
            tuple(sorted(terminal[old])) for old in order
        )

        labels: list[tuple[str, ...]] = [()] * n_states
        for q in range(n_states):
            for sym, child in goto[q].items():
                labels[child] = labels[q] + (self.vocabulary[sym],)

        # 3. Failure function, output function and the complete δ table.
        #    BFS numbering guarantees fail(q) < q, so a single ascending pass works.
        n_symbols = len(self.alphabet)
        n_vocab = len(self.vocabulary)
        fail = [0] * n_states
        output: list[tuple[int, ...]] = [()] * n_states
        delta = [[0] * n_symbols for _ in range(n_states)]
        for q in range(n_states):
            if q != 0:
                output[q] = self._terminal[q] + output[fail[q]]
            row = delta[q]
            for sym in range(n_vocab):
                if sym in goto[q]:
                    row[sym] = goto[q][sym]
                elif q != 0:
                    row[sym] = delta[fail[q]][sym]
                else:
                    row[sym] = 0
            row[self.skip_symbol] = q
            row[self.other_symbol] = 0
            for sym, child in goto[q].items():
                fail[child] = 0 if q == 0 else delta[fail[q]][sym]

        self._goto = tuple(goto)
        self.labels: tuple[tuple[str, ...], ...] = tuple(labels)
        self.fail: tuple[int, ...] = tuple(fail)
        self.output: tuple[tuple[int, ...], ...] = tuple(output)
        self.delta: tuple[tuple[int, ...], ...] = tuple(tuple(r) for r in delta)
        self.accepting: frozenset[int] = frozenset(q for q in range(n_states) if output[q])
        self.initial_state = 0

    # ---------------------------------------------------------------- queries
    @property
    def num_states(self) -> int:
        return len(self.delta)

    def symbol_of(self, token: str) -> int:
        """Map an arbitrary input token to its alphabet symbol index."""
        if token in self.skip_tokens:
            return self.skip_symbol
        return self._symbol_index.get(token, self.other_symbol)

    def symbol_name(self, symbol: int) -> str:
        return self.alphabet[symbol]

    def step(self, state: int, token: str) -> int:
        """δ(state, symbol_of(token)) — a single table lookup."""
        return self.delta[state][self.symbol_of(token)]

    def is_trie_edge(self, state: int, symbol: int) -> bool:
        return symbol in self._goto[state]

    def state_label(self, state: int) -> str:
        return " ".join(self.labels[state]) if state else "ε"

    def transition_kind(self, from_state: int, symbol: int, to_state: int) -> str:
        if symbol == self.skip_symbol:
            return "skip"
        if symbol != self.other_symbol and symbol in self._goto[from_state]:
            return "trie"
        if to_state == 0:
            return "reset"
        return "failure"

    def nontrivial_transitions(self, state: int) -> list[tuple[str, int, str]]:
        """All (symbol, target, kind) with a target other than q0 and not a skip loop.

        Every symbol not listed goes to q0 (or loops, for ⟨skip⟩); this is
        the compact way to print a row of the otherwise dense table.
        """
        row = self.delta[state]
        result = []
        for sym in range(len(self.vocabulary)):
            target = row[sym]
            if target != 0:
                result.append((self.vocabulary[sym], target, self.transition_kind(state, sym, target)))
        return result

    def describe(self) -> dict:
        trie_edges = sum(len(g) for g in self._goto)
        return {
            "num_states": self.num_states,
            "alphabet_size": len(self.alphabet),
            "vocabulary_size": len(self.vocabulary),
            "num_accepting_states": len(self.accepting),
            "num_patterns": len(self.patterns),
            "trie_edges": trie_edges,
            "transition_table_entries": self.num_states * len(self.alphabet),
            "max_pattern_length": max((len(p) for p in self.patterns), default=0),
            "initial_state": self.initial_state,
            "skip_tokens": sorted(self.skip_tokens),
        }

    # -------------------------------------------------------------------- run
    def run(
        self,
        tokens: Sequence[str],
        *,
        trace: bool = False,
        max_trace_steps: int | None = None,
    ) -> RunResult:
        """Feed ``tokens`` through the DFA from q0 and collect every match.

        Overlapping and nested matches are all reported: at each step the
        output set λ(q) already contains every pattern that is a suffix of
        the input read so far.
        """
        state = self.initial_state
        matches: list[AutomatonMatch] = []
        steps: list[TraceStep] = []
        truncated = False
        consumed_positions: list[int] = []  # positions of non-skip tokens
        visited = {state}
        delta = self.delta
        skip = self.skip_symbol

        for pos, token in enumerate(tokens):
            symbol = self.symbol_of(token)
            if symbol == skip:
                next_state = state
                emitted: tuple[int, ...] = ()
            else:
                consumed_positions.append(pos)
                next_state = delta[state][symbol]
                emitted = self.output[next_state]
                for pid in emitted:
                    length = len(self.patterns[pid])
                    matches.append(
                        AutomatonMatch(
                            pattern_id=pid,
                            start_pos=consumed_positions[-length],
                            end_pos=pos,
                            state=next_state,
                        )
                    )
            visited.add(next_state)
            if trace:
                if max_trace_steps is None or len(steps) < max_trace_steps:
                    steps.append(
                        TraceStep(
                            step=len(steps) + 1,
                            position=pos,
                            token=token,
                            symbol=self.alphabet[symbol],
                            from_state=state,
                            to_state=next_state,
                            transition=self.transition_kind(state, symbol, next_state),
                            outputs=emitted,
                        )
                    )
                else:
                    truncated = True
            state = next_state

        return RunResult(
            final_state=state,
            matches=tuple(matches),
            trace=tuple(steps),
            trace_truncated=truncated,
            states_visited=len(visited),
        )
